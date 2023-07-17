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
	ocroutev1 "github.com/openshift/api/route/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/common"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/logger"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/scan"
)

const (
	//  The actual ingress controller pod is usually unknown and not available in the input resources for the analysis.
	// IngressPodName and IngressPodNamespace are used to represent  that pod with those placeholder values for name and namespace.
	IngressPodName      = "ingress-controller"
	IngressPodNamespace = "ingress-controller-ns"
)

type serviceInfo struct {
	serviceName       string
	serviceTargetPort intstr.IntOrString
}

// IngressAnalyzer provides API to analyze Ingress/Route resources, to allow inferring potential connectivity
// from ingress-controller to pods in the cluster
type IngressAnalyzer struct {
	logger                  logger.Logger
	pe                      *eval.PolicyEngine                  // holds the workload peers relevant to the analysis
	servicesToPeersMap      map[string]map[string][]eval.Peer   // map from namespace to map from service name to its selected workloads
	routesToServicesMap     map[string]map[string][]string      // map from namespace to map from route name to its target service names
	k8sIngressToServicesMap map[string]map[string][]serviceInfo // map from namespace to map from k8s ingress object name to
	// its target services
}

// NewIngressAnalyzerWithObjects returns a new IngressAnalyzer with relevant objects
func NewIngressAnalyzerWithObjects(objects []scan.K8sObject, pe *eval.PolicyEngine, l logger.Logger) (*IngressAnalyzer, error) {
	ia := &IngressAnalyzer{
		servicesToPeersMap:      make(map[string]map[string][]eval.Peer),
		routesToServicesMap:     make(map[string]map[string][]string),
		k8sIngressToServicesMap: make(map[string]map[string][]serviceInfo),
		logger:                  l,
		pe:                      pe,
	}

	var err error
	for _, obj := range objects {
		switch obj.Kind {
		case scan.Service:
			err = ia.mapServiceToPeers(obj.Service)
		case scan.Route:
			ia.mapRouteToServices(obj.Route)
		case scan.Ingress:
			ia.mapk8sIngressToServices(obj.Ingress)
		}
		if err != nil {
			return nil, err
		}
	}
	return ia, err
}

// IsEmpty returns whether there are no services to consider for Ingress analysis
func (ia *IngressAnalyzer) IsEmpty() bool {
	return len(ia.servicesToPeersMap) == 0
}

/////////////////////////////////////////////////////////////////////////////////////////////////
// services analysis

const missingSelectorWarning = "K8s Service without selectors is not supported"

// mapServiceToPeers populates servicesToPeersMap
func (ia *IngressAnalyzer) mapServiceToPeers(svc *corev1.Service) error {
	// get peers selected by the service selectors
	peers, err := ia.getServicePeers(svc)
	if err != nil {
		return err
	}
	if len(peers) == 0 {
		// service was ignored
		return nil
	}
	if _, ok := ia.servicesToPeersMap[svc.Namespace]; !ok {
		ia.servicesToPeersMap[svc.Namespace] = make(map[string][]eval.Peer)
	}
	ia.servicesToPeersMap[svc.Namespace][svc.Name] = peers
	return nil
}

// getServicePeers given a service return its selected peers
func (ia *IngressAnalyzer) getServicePeers(svc *corev1.Service) ([]eval.Peer, error) {
	svcStr := types.NamespacedName{Name: svc.Name, Namespace: svc.Namespace}.String()
	if svc.Spec.Selector == nil {
		ia.logger.Warnf("ignoring " + scan.Service + " " + svcStr + ": " + missingSelectorWarning)
		return nil, nil
	}
	svcLabelsSelector, err := convertServiceSelectorToLabelSelector(svc.Spec.Selector)
	if err != nil {
		return nil, err
	}
	return ia.pe.GetSelectedPeers(svcLabelsSelector, svc.Namespace), nil
}

// utility func
// convertServiceSelectorToLabelSelector converts service selector to LabelsSelector
func convertServiceSelectorToLabelSelector(svcSelector map[string]string) (labels.Selector, error) {
	labelsSelector := metav1.LabelSelector{MatchLabels: svcSelector}
	selectorRes, err := metav1.LabelSelectorAsSelector(&labelsSelector)
	if err != nil {
		return nil, err
	}
	return selectorRes, nil
}

////////////////////////////////////////////////////////////////////////////////////////////////
// routes analysis

const (
	allowedTargetKind      = scan.Service
	routeTargetKindWarning = "ignoring target with unsupported kind"
	routeBackendsWarning   = "ignoring alternate backend without Service "
)

// mapRouteToServices populates routesToServicesMap
func (ia *IngressAnalyzer) mapRouteToServices(rt *ocroutev1.Route) {
	services := ia.getRouteServices(rt)
	if len(services) == 0 { // all route targets were ignored
		return
	}
	if _, ok := ia.routesToServicesMap[rt.Namespace]; !ok {
		ia.routesToServicesMap[rt.Namespace] = make(map[string][]string)
	}
	ia.routesToServicesMap[rt.Namespace][rt.Name] = services
}

// getRouteServices given Route object returns its targeted services names
func (ia *IngressAnalyzer) getRouteServices(rt *ocroutev1.Route) []string {
	routeStr := types.NamespacedName{Namespace: rt.Namespace, Name: rt.Name}.String()
	targetServices := make([]string, 0, len(rt.Spec.AlternateBackends)+1)
	// Currently, only 'Service' is allowed as the kind of target that the route is referring to.
	if rt.Spec.To.Kind != "" && rt.Spec.To.Kind != allowedTargetKind {
		ia.logger.Warnf(scan.Route + " " + routeStr + ": " + routeTargetKindWarning)
	} else {
		targetServices = append(targetServices, rt.Spec.To.Name)
	}

	for _, backend := range rt.Spec.AlternateBackends {
		if backend.Kind != "" && backend.Kind != allowedTargetKind {
			ia.logger.Warnf(scan.Route + " " + routeStr + ": " + routeBackendsWarning)
		} else {
			targetServices = append(targetServices, backend.Name)
		}
	}
	return targetServices
}

// ///////////////////////////////////////////////////////////////////////////////////////////////
// k8s Ingress objects analysis

const (
	defaultBackendWarning = "ignoring default backend"
	ruleBackendWarning    = "ignoring rule backend without Service"
)

// mapk8sIngressToServices populates k8sIngressToServicesMap
func (ia *IngressAnalyzer) mapk8sIngressToServices(ing *netv1.Ingress) {
	services := ia.getk8sIngressServices(ing)
	if len(services) == 0 { // all ingress backends were ignored
		return
	}
	if _, ok := ia.k8sIngressToServicesMap[ing.Namespace]; !ok {
		ia.k8sIngressToServicesMap[ing.Namespace] = make(map[string][]serviceInfo)
	}
	ia.k8sIngressToServicesMap[ing.Namespace][ing.Name] = services
}

// getk8sIngressServices given k8s-Ingress object returns its targeted services info
func (ia *IngressAnalyzer) getk8sIngressServices(ing *netv1.Ingress) []serviceInfo {
	ingressStr := types.NamespacedName{Namespace: ing.Namespace, Name: ing.Name}.String()
	backendServices := make([]serviceInfo, 0)
	// if DefaultBackend is provided add its service info to the result
	if ing.Spec.DefaultBackend != nil {
		if ing.Spec.DefaultBackend.Service == nil {
			ia.logger.Warnf(scan.Ingress + " " + ingressStr + ": " + defaultBackendWarning)
		} else {
			backendServices = append(backendServices, getServiceInfo(ing.Spec.DefaultBackend.Service))
		}
	}
	// add service names from the Ingress rules
	for _, rule := range ing.Spec.Rules {
		for _, path := range rule.IngressRuleValue.HTTP.Paths {
			if path.Backend.Service == nil {
				ia.logger.Warnf(scan.Ingress + " " + ingressStr + ": " + ruleBackendWarning)
			} else {
				backendServices = append(backendServices, getServiceInfo(path.Backend.Service))
			}
		}
	}
	return backendServices
}

// utility func
// getServiceInfo returns serviceInfo struct (name and port) from a given Ingress backend service
func getServiceInfo(backendService *netv1.IngressServiceBackend) serviceInfo {
	res := serviceInfo{serviceName: backendService.Name}
	// Port.Name and Port.Number are mutually exclusive
	if backendService.Port.Name != "" {
		res.serviceTargetPort.StrVal = backendService.Port.Name
	} else {
		res.serviceTargetPort.IntVal = backendService.Port.Number
	}
	return res
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Ingress allowed connections

// AllowedIngressConnections returns a map of the possible connections from ingress-controller pod to workload peers,
// as inferred from Ingress and Route resources. The map is from a workload name to its connection object.
func (ia *IngressAnalyzer) AllowedIngressConnections() (map[string]common.Connection, error) {
	// if there is at least one route/ ingress object that targets a service which selects a dst peer,
	// then we have ingress connections to that peer

	// get all targeted workload peers and compute allowed conns of each workload peer
	// 1. from routes
	routesResult := ia.allowedIngressConnectionsByRoutes()
	// 2. from k8s-ingress objects
	ingressResult, err := ia.allowedIngressConnectionsByk8sIngress()
	if err != nil {
		return nil, err
	}

	// merge the map results from routes and k8s-ingress objects
	mergeResults(routesResult, ingressResult)
	return ingressResult, nil
}

// utility func
// mergeResults merges routesMap into ingressMap , since routesMap may be wider with peers connections
func mergeResults(routesMap, ingressMap map[string]common.Connection) {
	for k, v := range routesMap {
		ingressMap[k] = v
	}
}

/*************************************************************************************************/
// Ingress allowed connections by Routes

// allowedIngressConnectionsByRoutes returns map from peers names to the allowed ingress connections based on Route objects rules
func (ia *IngressAnalyzer) allowedIngressConnectionsByRoutes() map[string]common.Connection {
	res := make(map[string]common.Connection)
	for ns, objSvcMap := range ia.routesToServicesMap {
		// if there are no services in same namespace of the route, the routes in this ns will be skipped
		if _, ok := ia.servicesToPeersMap[ns]; !ok {
			continue
		}

		for _, svcList := range objSvcMap {
			routeTargetPeers := ia.getRouteTargetedPeers(ns, svcList)
			// avoid duplicates in the result
			for _, peer := range routeTargetPeers {
				if _, ok := res[peer.String()]; !ok {
					res[peer.String()] = eval.GetPeerExposedTCPConnections(peer)
				}
			}
		}
	}
	return res
}

// getRouteTargetedPeers returns all peers which are targeted by routes objects in their namespace
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

/*************************************************************************************************/
// Ingress allowed connections by k8s-ingress objects

// allowedIngressConnectionsByk8sIngress returns map from peers names to the allowed ingress connections based on k8s-Ingress objects rules
func (ia *IngressAnalyzer) allowedIngressConnectionsByk8sIngress() (map[string]common.Connection, error) {
	medRes := make(map[string]*common.ConnectionSet)
	for ns, objSvcMap := range ia.k8sIngressToServicesMap {
		// if there are no services in same namespace of the Ingress, the ingress objects in this ns will be skipped
		if _, ok := ia.servicesToPeersMap[ns]; !ok {
			continue
		}

		for _, svcList := range objSvcMap {
			ingressObjTargetPeersAndPorts, err := ia.getIngressObjectTargetedPeersAndPorts(ns, svcList)
			if err != nil {
				return nil, err
			}
			// avoid duplicates in the result, consider the different ports supported
			for peer, pConn := range ingressObjTargetPeersAndPorts {
				if _, ok := medRes[peer.String()]; !ok {
					medRes[peer.String()] = pConn
				} else {
					medRes[peer.String()].Union(pConn)
				}
			}
		}
	}
	// convert all conns to common.Connection for outer representation
	res := make(map[string]common.Connection, len(medRes))
	for peerStr, pConn := range medRes {
		res[peerStr] = pConn
	}
	return res, nil
}

// getIngressObjectTargetedPeersAndPorts returns map from peers which are targeted by Ingress objects in their namespace to
// the Ingress required connections
func (ia *IngressAnalyzer) getIngressObjectTargetedPeersAndPorts(ns string,
	svcList []serviceInfo) (map[eval.Peer]*common.ConnectionSet, error) {
	res := make(map[eval.Peer]*common.ConnectionSet)
	for _, svc := range svcList {
		peers, ok := ia.servicesToPeersMap[ns][svc.serviceName]
		if !ok {
			ia.logger.Warnf("ignoring target service " + svc.serviceName + " : service not found")
		}
		for _, peer := range peers {
			permittedPeerConn := common.MakeConnectionSet(false)
			// check if its TCP conns contains the required port
			peerTCPConn := eval.GetPeerExposedTCPConnections(peer)
			if peerTCPConn.Contains(svc.serviceTargetPort.String(), string(corev1.ProtocolTCP)) {
				permittedPort := common.PortSet{}
				var portNum int
				if svc.serviceTargetPort.Type == intstr.Int {
					portNum = svc.serviceTargetPort.IntValue()
				} else {
					portInt, err := ia.pe.ConvertPeerNamedPort(svc.serviceTargetPort.StrVal, peer)
					if err != nil {
						return nil, err
					}
					portNum = int(portInt)
				}
				permittedPort.AddPort(intstr.FromInt(portNum))
				permittedPeerConn.AddConnection(corev1.ProtocolTCP, permittedPort)
				if _, ok := res[peer]; !ok {
					res[peer] = permittedPeerConn
				} else {
					res[peer].Union(permittedPeerConn)
				}
			}
		}
	}
	return res, nil
}
