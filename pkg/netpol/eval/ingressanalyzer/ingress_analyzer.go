// Copyright 2022
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ingressanalyzer

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	ocroutev1 "github.com/openshift/api/route/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval/internal/k8s"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/scan"
)

const (
	ingressPodName = "ingress-controller"
	ingressPodNs   = "ingress-controller-ns"
)

type (
	IngressAnalyzer struct {
		pe *eval.PolicyEngine // a struct type that includes the podsMap and
		// some functionality on pods and namespaces which is required for ingress analyzing
		servicesMap map[string]map[string]*k8s.Service // map from namespace to map from service name to its object
		routesMap   map[string]map[string]*k8s.Route   // map from namespace to map from route name to its object
		// k8sIngressMap map[string]map[string]*k8s.Ingress // map from namespace to map from ingress name to its object
	}
)

// NewIngressAnalyzer returns a new IngressAnalyzer with an empty initial state
func NewIngressAnalyzer() *IngressAnalyzer {
	return &IngressAnalyzer{
		pe:          eval.NewPolicyEngine(),
		servicesMap: make(map[string]map[string]*k8s.Service),
		routesMap:   make(map[string]map[string]*k8s.Route),
	}
}

// NewIngressAnalyzerWithObjects returns a new IngressAnalyzer with relevant objects
func NewIngressAnalyzerWithObjects(objects []scan.K8sObject, pe *eval.PolicyEngine) (*IngressAnalyzer, error) {
	ia := NewIngressAnalyzer()
	ia.pe = pe
	var err error
	for _, obj := range objects {
		switch obj.Kind {
		case scan.Service:
			err = ia.upsertService(obj.Service)
		case scan.Route:
			err = ia.upsertRoute(obj.Route)
		}
		if err != nil {
			return nil, err
		}
	}
	return ia, err
}

// GetIngressControllerPod creates a new ingress-controller pod, as the source of all ingress connections
func (ia *IngressAnalyzer) GetIngressControllerPod() eval.Peer {
	ingressPod := &k8s.Pod{
		Name:      ingressPodName,
		Namespace: ingressPodNs,
	}
	return &k8s.WorkloadPeer{Pod: ingressPod}
}

func (ia *IngressAnalyzer) upsertService(svc *corev1.Service) error {
	svcObj, err := k8s.ServiceFromCoreObject(svc)
	if err != nil {
		return err
	}
	if _, ok := ia.servicesMap[svcObj.Namespace]; !ok {
		ia.servicesMap[svcObj.Namespace] = make(map[string]*k8s.Service)
	}
	ia.servicesMap[svcObj.Namespace][svcObj.Name] = svcObj
	return nil
}

func (ia *IngressAnalyzer) upsertRoute(rt *ocroutev1.Route) error {
	routeObj, err := k8s.RouteFromOCObject(rt)
	if err != nil {
		return err
	}
	if _, ok := ia.routesMap[routeObj.Namespace]; !ok {
		ia.routesMap[routeObj.Namespace] = make(map[string]*k8s.Route)
	}
	ia.routesMap[routeObj.Namespace][routeObj.Name] = routeObj
	return nil
}

// ///////////////////////////////////////////////////////////////////////////////////
// map service to pods

func (ia *IngressAnalyzer) getServicePods(svcName, svcNamespace string) ([]*k8s.Pod, error) {
	svc := ia.getServiceFromServiceNameAndNamespace(svcName, svcNamespace)
	// todo: should return error if the service not found?
	if svc == nil {
		svcStr := types.NamespacedName{Namespace: svcNamespace, Name: svcName}
		return nil, fmt.Errorf("service does not exist: %s", svcStr)
	}
	svcLabelsSelect, err := svc.ServicSelectorsAsLabelSelector()
	if err != nil {
		return nil, err
	}
	res := make([]*k8s.Pod, 0)
	for _, pod := range ia.pe.GetPodsMap() {
		if pod.Namespace != svcNamespace {
			continue
		}
		if svcLabelsSelect.Matches(labels.Set(pod.Labels)) {
			res = append(res, pod)
		}
	}
	return res, nil
}

func (ia *IngressAnalyzer) getServiceFromServiceNameAndNamespace(svcName, svcNamespace string) *k8s.Service {
	if svcMap, ok := ia.servicesMap[svcNamespace]; ok {
		return svcMap[svcName]
	}
	return nil
}

////////////////////////////////////////////////////////////////////////////////////
// Ingress connections

func (ia *IngressAnalyzer) getRouteTargetedPods(namespace string, svcList []string) []*k8s.Pod {
	var res []*k8s.Pod
	for _, svc := range svcList {
		svcPods, err := ia.getServicePods(svc, namespace)
		if err != nil {
			continue // can not get targeted pods of this service
		}
		res = append(res, svcPods...)
	}
	return res
}

// AllowedIngressConnections returns map of the allowed external ingress-controller's connections of each targeted peer
func (ia *IngressAnalyzer) AllowedIngressConnections() map[*k8s.Pod]eval.Connection {
	// if there is at least one route/ ingress object that targets a service which selects a dst peer,
	// then we have an ingress conns to the peer

	// get all targeted pods
	targetedPodsSet := make(map[*k8s.Pod]struct{}, 0)
	for ns, rtMap := range ia.routesMap {
		// if there are no services in same namespace of the route, the routes in this ns will be skipped
		if _, ok := ia.servicesMap[ns]; !ok {
			continue
		}
		for _, route := range rtMap {
			routeTargetPods := ia.getRouteTargetedPods(ns, route.TargetServices)
			// avoid dups in the targetedPodsSet
			for _, pod := range routeTargetPods {
				if _, ok := targetedPodsSet[pod]; !ok {
					targetedPodsSet[pod] = struct{}{}
				}
			}
		}
	}
	// compute allowed conns of each pod
	res := make(map[*k8s.Pod]eval.Connection)
	for pod := range targetedPodsSet {
		res[pod] = eval.GetConnectionObject(pod.AllowedConnectionsToPod())
	}
	return res
}
