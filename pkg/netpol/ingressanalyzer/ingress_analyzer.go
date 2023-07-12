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
	"errors"

	ocroutev1 "github.com/openshift/api/route/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/logger"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/scan"
)

// IngressAnalyzer provides API to analyze Ingress/Route resources, to allow inferring potential connectivity
// from ingress-controller to pods in the cluster
type IngressAnalyzer struct {
	logger logger.Logger
	pe     *eval.PolicyEngine // a struct type that includes the podsMap and
	// some functionality on pods and namespaces which is required for ingress analyzing
	servicesToPeersMap      map[string]map[string][]eval.Peer // map from namespace to map from service name to its selected workloads
	routesToServicesMap     map[string]map[string][]string    // map from namespace to map from route name to its target service names
	k8sIngressToServicesMap map[string]map[string][]string    // map from namespace to map from k8s ingress object name to
	// its backend service names
}

// NewIngressAnalyzerWithObjects returns a new IngressAnalyzer with relevant objects
func NewIngressAnalyzerWithObjects(objects []scan.K8sObject, pe *eval.PolicyEngine, l logger.Logger) (*IngressAnalyzer, error) {
	ia := &IngressAnalyzer{
		servicesToPeersMap:      make(map[string]map[string][]eval.Peer),
		routesToServicesMap:     make(map[string]map[string][]string),
		k8sIngressToServicesMap: make(map[string]map[string][]string),
		logger:                  l,
		pe:                      pe,
	}

	var err error
	for _, obj := range objects {
		switch obj.Kind {
		case scan.Service:
			err = ia.mapServiceToPeers(obj.Service)
		case scan.Route:
			err = ia.mapRouteToServices(obj.Route)
		case scan.Ingress:
			err = ia.mapk8sIngressToServices(obj.Ingress)
		}
		if err != nil {
			return nil, err
		}
	}
	return ia, err
}

/////////////////////////////////////////////////////////////////////////////////////////////////
// services analysis

const (
	selectorError        = "selector conversion error"
	missingSelectorError = "error : K8s Service without selectors is not supported"
)

// this function populates servicesToPeersMap
func (ia *IngressAnalyzer) mapServiceToPeers(svc *corev1.Service) error {
	// get peers selected by the service selectors
	peers, err := ia.getServicePeers(svc)
	if err != nil {
		return err
	}
	if _, ok := ia.servicesToPeersMap[svc.Namespace]; !ok {
		ia.servicesToPeersMap[svc.Namespace] = make(map[string][]eval.Peer)
	}
	ia.servicesToPeersMap[svc.Namespace][svc.Name] = peers
	return nil
}

func (ia *IngressAnalyzer) getServicePeers(svc *corev1.Service) ([]eval.Peer, error) {
	svcStr := types.NamespacedName{Name: svc.Name, Namespace: svc.Namespace}.String()
	if svc.Spec.Selector == nil {
		return nil, errors.New(scan.Service + " " + svcStr + " " + missingSelectorError)
	}
	svcLabelsSelector, err := convertServiceSelectorToLabelSelector(svc.Spec.Selector, svcStr)
	if err != nil {
		return nil, err
	}
	return ia.pe.GetSelectedPeers(svcLabelsSelector, svc.Namespace), nil
}

// utility func
func convertServiceSelectorToLabelSelector(svcSelector map[string]string, svcStr string) (labels.Selector, error) {
	labelsSelector := metav1.LabelSelector{MatchLabels: svcSelector}
	selectorRes, err := metav1.LabelSelectorAsSelector(&labelsSelector)
	if err != nil {
		return nil, errors.New(scan.Service + " " + svcStr + " " + selectorError)
	}
	return selectorRes, nil
}

////////////////////////////////////////////////////////////////////////////////////////////////
// routes analysis

const (
	allowedTargetKind  = scan.Service
	routeTargetKindErr = "target kind error"
	routeBackendsErr   = "alternate backends error"
)

// this function populates routesToServicesMap
func (ia *IngressAnalyzer) mapRouteToServices(rt *ocroutev1.Route) error {
	services, err := getRouteServices(rt)
	if err != nil {
		return err
	}
	if _, ok := ia.routesToServicesMap[rt.Namespace]; !ok {
		ia.routesToServicesMap[rt.Namespace] = make(map[string][]string)
	}
	ia.routesToServicesMap[rt.Namespace][rt.Name] = services
	return nil
}

func getRouteServices(rt *ocroutev1.Route) ([]string, error) {
	routeStr := types.NamespacedName{Namespace: rt.Namespace, Name: rt.Name}.String()
	// Currently, only 'Service' is allowed as the kind of target that the route is referring to.
	if rt.Spec.To.Kind != "" && rt.Spec.To.Kind != allowedTargetKind {
		return nil, errors.New(scan.Route + " " + routeStr + ": " + routeTargetKindErr)
	}

	targetServices := make([]string, len(rt.Spec.AlternateBackends)+1)
	targetServices[0] = rt.Spec.To.Name
	for i, backend := range rt.Spec.AlternateBackends {
		if backend.Kind != "" && backend.Kind != allowedTargetKind {
			return nil, errors.New(scan.Route + " " + routeStr + ": " + routeBackendsErr)
		}
		targetServices[i+1] = backend.Name
	}
	return targetServices, nil
}

// ///////////////////////////////////////////////////////////////////////////////////////////////
// k8s Ingress objects analysis

const (
	defaultBackendError = "default backend kind error"
	ruleBackendError    = "rule's backend kind error"
)

func (ia *IngressAnalyzer) mapk8sIngressToServices(ing *netv1.Ingress) error {
	services, err := getk8sIngressServices(ing)
	if err != nil {
		return err
	}
	if _, ok := ia.k8sIngressToServicesMap[ing.Namespace]; !ok {
		ia.k8sIngressToServicesMap[ing.Namespace] = make(map[string][]string)
	}
	ia.k8sIngressToServicesMap[ing.Namespace][ing.Name] = services
	return nil
}

func getk8sIngressServices(ing *netv1.Ingress) ([]string, error) {
	ingressStr := types.NamespacedName{Namespace: ing.Namespace, Name: ing.Name}.String()
	backendServices := make([]string, 0)
	// if DefaultBackend is provided add its service name to the result
	if ing.Spec.DefaultBackend != nil {
		if ing.Spec.DefaultBackend.Service == nil { // i.e backend.Resource is not nil
			// Currently, only IngressBackend with Service is supported
			return nil, errors.New(scan.Ingress + " " + ingressStr + ": " + defaultBackendError)
		}
		backendServices[0] = ing.Spec.DefaultBackend.Service.Name
	}
	// add service names from the Ingress rules
	for _, rule := range ing.Spec.Rules {
		for _, path := range rule.IngressRuleValue.HTTP.Paths {
			if path.Backend.Service == nil {
				return nil, errors.New(scan.Ingress + " " + ingressStr + ": " + ruleBackendError)
			}
			backendServices = append(backendServices, path.Backend.Service.Name)
		}
	}
	return backendServices, nil
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Ingress allowed connections

// AllowedIngressConnections returns a map of the possible connections from ingress-controller pod to workload peers,
// as inferred from Ingress and Route resources. The map is from a workload name to its connection object.
func (ia *IngressAnalyzer) AllowedIngressConnections() map[string]eval.Connection {
	// if there is at least one route/ ingress object that targets a service which selects a dst peer,
	// then we have ingress connections to that peer

	// get all targeted workload peers and compute allowed conns of each workload peer
	// 1. from routes
	routesResult := ia.allowedIngressConnectionsByIngressObjects(scan.Route)
	// 2. from k8s-ingress objects
	ingressResult := ia.allowedIngressConnectionsByIngressObjects(scan.Ingress)

	// merge the map results from routes and k8s-ingress objects
	mergeResults(routesResult, ingressResult)
	return routesResult
}

func (ia *IngressAnalyzer) allowedIngressConnectionsByIngressObjects(objType string) map[string]eval.Connection {
	mapToIterate := ia.routesToServicesMap
	if objType == scan.Ingress {
		mapToIterate = ia.k8sIngressToServicesMap
	}
	res := make(map[string]eval.Connection)
	for ns, objSvcMap := range mapToIterate {
		// if there are no services in same namespace of the route, the routes in this ns will be skipped
		if _, ok := ia.servicesToPeersMap[ns]; !ok {
			continue
		}

		for _, svcList := range objSvcMap {
			ingressObjTargetPeers := ia.getIngressObjectTargetedPeers(ns, svcList)
			// avoid duplicates in the result
			for _, peer := range ingressObjTargetPeers {
				peerStr := types.NamespacedName{Name: peer.Name(), Namespace: peer.Namespace()}.String()
				if _, ok := res[peerStr]; !ok {
					res[peerStr] = ia.pe.GetPeerExposedProtocolsAndPorts(peer)
				}
			}
		}
	}
	return res
}

func (ia *IngressAnalyzer) getIngressObjectTargetedPeers(ns string, svcList []string) []eval.Peer {
	var res []eval.Peer
	for _, svc := range svcList {
		peers, ok := ia.servicesToPeersMap[ns][svc]
		if !ok {
			ia.logger.Warnf("ignoring target service " + svc + " : service not found")
		}
		res = append(res, peers...)
	}
	return res
}

// utility func
func mergeResults(map1, map2 map[string]eval.Connection) {
	for k, v := range map2 {
		map1[k] = v
	}
}
