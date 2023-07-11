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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/logger"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/scan"
)

// IngressAnalyzer provides API to analyze Ingress/Route resources, to allow inferring potential connectivity from ingress-controller to pods in the cluster
type IngressAnalyzer struct {
	logger logger.Logger
	pe     *eval.PolicyEngine // a struct type that includes the podsMap and
	// some functionality on pods and namespaces which is required for ingress analyzing
	servicesToPeersMap  map[string]map[string][]eval.Peer // map from namespace to map from service name to its selected workloads
	routesToServicesMap map[string]map[string][]string    // map from namespace to map from route name to its target services names
}

// NewIngressAnalyzer returns a new IngressAnalyzer with an empty initial state
func NewIngressAnalyzer() *IngressAnalyzer {
	return &IngressAnalyzer{
		logger:              logger.NewDefaultLogger(),
		pe:                  eval.NewPolicyEngine(),
		servicesToPeersMap:  make(map[string]map[string][]eval.Peer),
		routesToServicesMap: make(map[string]map[string][]string),
	}
}

// NewIngressAnalyzerWithObjects returns a new IngressAnalyzer with relevant objects
func NewIngressAnalyzerWithObjects(objects []scan.K8sObject, pe *eval.PolicyEngine, l logger.Logger) (*IngressAnalyzer, error) {
	ia := NewIngressAnalyzer()
	ia.logger = l
	ia.pe = pe
	var err error
	for _, obj := range objects {
		switch obj.Kind {
		case scan.Service:
			err = ia.mapServiceToPeers(obj.Service)
		case scan.Route:
			err = ia.mapRouteToServices(obj.Route)
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

func (ia *IngressAnalyzer) mapServiceToPeers(svc *corev1.Service) error {
	// get peers selected by the service selctors
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
	svcLabelsSelector, err := convertServiceSelctorToLabelSelector(svc.Spec.Selector, svcStr)
	if err != nil {
		return nil, err
	}
	res := make([]eval.Peer, 0)
	peers, err := ia.pe.GetPeersList()
	if err != nil {
		return nil, err
	}
	for _, peer := range peers {
		if peer.IsPeerIPType() {
			continue
		}
		podPeer, err := ia.pe.ConvertWorkloadPeerToPodPeer(peer)
		if err != nil {
			return nil, err
		}
		if podPeer.Namespace() != svc.Namespace {
			continue
		}
		if svcLabelsSelector.Matches(labels.Set(podPeer.Pod.Labels)) {
			res = append(res, peer)
		}
	}
	return res, nil
}

// utility func
func convertServiceSelctorToLabelSelector(svcSelect map[string]string, svcStr string) (labels.Selector, error) {
	labelsSelector := metav1.LabelSelector{MatchLabels: svcSelect}
	selectorRes, err := metav1.LabelSelectorAsSelector(&labelsSelector)
	if err != nil {
		return nil, errors.New(scan.Service + " " + svcStr + " " + selectorError)
	}
	return selectorRes, nil
}

// //////////////////////////////////////////////////////////////////////////////////////////////
// routes analyze

const (
	maxBackendServices = 3
	allowedTargetKind  = scan.Service
	routeTargetKindErr = "target kind error"
	routeBackendsErr   = "alternate backends error"
)

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
	if len(rt.Spec.AlternateBackends) > maxBackendServices {
		return nil, errors.New(scan.Route + " " + routeStr + ": " + routeBackendsErr)
	}

	targetSvcs := make([]string, len(rt.Spec.AlternateBackends)+1)
	targetSvcs[0] = rt.Spec.To.Name
	for i, backend := range rt.Spec.AlternateBackends {
		if backend.Kind != "" && backend.Kind != allowedTargetKind {
			return nil, errors.New(scan.Route + " " + routeStr + ": " + routeBackendsErr)
		}
		targetSvcs[i+1] = backend.Name
	}
	return targetSvcs, nil
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Ingress allowed conns

// AllowedIngressConnections returns map of the allowed external ingress-controller's connections of each targeted peer
func (ia *IngressAnalyzer) AllowedIngressConnections() map[string]eval.Connection {
	// if there is at least one route/ ingress object that targets a service which selects a dst peer,
	// then we have an ingress conns to the peer

	// get all targeted peer pods
	targetedPeersSet := make(map[eval.Peer]bool, 0)
	for ns, rtSvcMap := range ia.routesToServicesMap {
		// if there are no services in same namespace of the route, the routes in this ns will be skipped
		if _, ok := ia.servicesToPeersMap[ns]; !ok {
			continue
		}

		for _, svcList := range rtSvcMap {
			routeTargetPeers := ia.getRouteTargetedPeers(ns, svcList)
			// avoid dups in the targetedPeersSet
			for _, peer := range routeTargetPeers {
				if !targetedPeersSet[peer] {
					targetedPeersSet[peer] = true
				}
			}
		}
	}

	// compute allowed conns of each peer pod
	res := make(map[string]eval.Connection)
	for peer := range targetedPeersSet {
		peerStr := types.NamespacedName{Name: peer.Name(), Namespace: peer.Namespace()}.String()
		peerPod, _ := ia.pe.ConvertWorkloadPeerToPodPeer(peer) // should not get error since all peers in ia.servicesToPeersMap are confirmed
		res[peerStr] = eval.GetConnectionObject(peerPod.GetAllowedConnectionsToPod())
	}
	return res
}

func (ia *IngressAnalyzer) getRouteTargetedPeers(ns string, svcList []string) []eval.Peer {
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
