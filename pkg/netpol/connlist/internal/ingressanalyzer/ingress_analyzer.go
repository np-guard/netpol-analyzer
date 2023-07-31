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
	"strconv"

	ocroutev1 "github.com/openshift/api/route/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

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
	// used to populate routesToServicesMap and k8sIngressToServicesMap with their target services info
	serviceName string
	servicePort intstr.IntOrString // service port name or port number
}

type peersAndPorts struct {
	// used to populate the servicesToPortsAndPeersMap Map with its ports and selected peers
	peers []eval.Peer
	ports []corev1.ServicePort
}

// IngressAnalyzer provides API to analyze Ingress/Route resources, to allow inferring potential connectivity
// from ingress-controller to pods in the cluster
type IngressAnalyzer struct {
	logger                     logger.Logger
	pe                         *eval.PolicyEngine                  // holds the workload peers relevant to the analysis
	servicesToPortsAndPeersMap map[string]map[string]peersAndPorts // map from namespace to map from service name to its ports and
	// its selected workloads
	routesToServicesMap     map[string]map[string][]serviceInfo // map from namespace to map from route name to its target service
	k8sIngressToServicesMap map[string]map[string][]serviceInfo // map from namespace to map from k8s ingress object name to
	// its target services
}

// NewIngressAnalyzerWithObjects returns a new IngressAnalyzer with relevant objects
func NewIngressAnalyzerWithObjects(objects []scan.K8sObject, pe *eval.PolicyEngine, l logger.Logger) (*IngressAnalyzer, error) {
	ia := &IngressAnalyzer{
		servicesToPortsAndPeersMap: make(map[string]map[string]peersAndPorts),
		routesToServicesMap:        make(map[string]map[string][]serviceInfo),
		k8sIngressToServicesMap:    make(map[string]map[string][]serviceInfo),
		logger:                     l,
		pe:                         pe,
	}

	var err error
	for _, obj := range objects {
		switch obj.Kind {
		case scan.Service:
			err = ia.mapServiceToPeers(obj.Service)
		case scan.Route:
			ia.mapRouteToServices(obj.Route)
		case scan.Ingress:
			ia.mapK8sIngressToServices(obj.Ingress)
		}
		if err != nil {
			return nil, err
		}
	}
	return ia, err
}

// IsEmpty returns whether there are no services to consider for Ingress analysis
func (ia *IngressAnalyzer) IsEmpty() bool {
	return len(ia.servicesToPortsAndPeersMap) == 0 ||
		(len(ia.routesToServicesMap) == 0 && len(ia.k8sIngressToServicesMap) == 0)
}

/////////////////////////////////////////////////////////////////////////////////////////////////
// services analysis

const (
	missingSelectorWarning = "K8s Service without selectors is not supported"
	whiteSpace             = " "
	colon                  = ": "
)

// mapServiceToPeers populates servicesToPortsAndPeersMap
func (ia *IngressAnalyzer) mapServiceToPeers(svc *corev1.Service) error {
	// get peers selected by the service selectors
	peers, err := ia.getServiceSelectedPeers(svc)
	if err != nil {
		return err
	}
	if len(peers) == 0 {
		// service was ignored
		return nil
	}
	if _, ok := ia.servicesToPortsAndPeersMap[svc.Namespace]; !ok {
		ia.servicesToPortsAndPeersMap[svc.Namespace] = make(map[string]peersAndPorts)
	}
	ia.servicesToPortsAndPeersMap[svc.Namespace][svc.Name] = peersAndPorts{peers: peers, ports: svc.Spec.Ports}
	return nil
}

// getServicePeers given a service return its selected peers
func (ia *IngressAnalyzer) getServiceSelectedPeers(svc *corev1.Service) ([]eval.Peer, error) {
	svcStr := types.NamespacedName{Name: svc.Name, Namespace: svc.Namespace}.String()
	if svc.Spec.Selector == nil {
		ia.logger.Warnf("ignoring " + scan.Service + whiteSpace + svcStr + colon + missingSelectorWarning)
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
		ia.routesToServicesMap[rt.Namespace] = make(map[string][]serviceInfo)
	}
	ia.routesToServicesMap[rt.Namespace][rt.Name] = services
}

// getRouteServices given Route object returns its targeted services names
func (ia *IngressAnalyzer) getRouteServices(rt *ocroutev1.Route) []serviceInfo {
	routeStr := types.NamespacedName{Namespace: rt.Namespace, Name: rt.Name}.String()
	targetServices := make([]serviceInfo, 0, len(rt.Spec.AlternateBackends)+1)
	var routeTargetPort intstr.IntOrString
	if rt.Spec.Port != nil {
		routeTargetPort = rt.Spec.Port.TargetPort
	}
	// Currently, only 'Service' is allowed as the kind of target that the route is referring to.
	if rt.Spec.To.Kind != "" && rt.Spec.To.Kind != allowedTargetKind {
		ia.logger.Warnf(scan.Route + whiteSpace + routeStr + colon + routeTargetKindWarning)
	} else {
		targetServices = append(targetServices, serviceInfo{serviceName: rt.Spec.To.Name, servicePort: routeTargetPort})
	}

	for _, backend := range rt.Spec.AlternateBackends {
		if backend.Kind != "" && backend.Kind != allowedTargetKind {
			ia.logger.Warnf(scan.Route + whiteSpace + routeStr + colon + routeBackendsWarning)
		} else {
			targetServices = append(targetServices, serviceInfo{serviceName: backend.Name, servicePort: routeTargetPort})
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
func (ia *IngressAnalyzer) mapK8sIngressToServices(ing *netv1.Ingress) {
	services := ia.getK8sIngressServices(ing)
	if len(services) == 0 { // all ingress backends were ignored
		return
	}
	if _, ok := ia.k8sIngressToServicesMap[ing.Namespace]; !ok {
		ia.k8sIngressToServicesMap[ing.Namespace] = make(map[string][]serviceInfo)
	}
	ia.k8sIngressToServicesMap[ing.Namespace][ing.Name] = services
}

// getk8sIngressServices given k8s-Ingress object returns its targeted services info
func (ia *IngressAnalyzer) getK8sIngressServices(ing *netv1.Ingress) []serviceInfo {
	ingressStr := types.NamespacedName{Namespace: ing.Namespace, Name: ing.Name}.String()
	backendServices := make([]serviceInfo, 0)
	// if DefaultBackend is provided add its service info to the result
	if ing.Spec.DefaultBackend != nil {
		if ing.Spec.DefaultBackend.Service == nil {
			ia.logger.Warnf(scan.Ingress + whiteSpace + ingressStr + colon + defaultBackendWarning)
		} else {
			backendServices = append(backendServices, getServiceInfo(ing.Spec.DefaultBackend.Service))
		}
	}
	// add service names from the Ingress rules
	for _, rule := range ing.Spec.Rules {
		for _, path := range rule.IngressRuleValue.HTTP.Paths {
			if path.Backend.Service == nil {
				ia.logger.Warnf(scan.Ingress + whiteSpace + ingressStr + colon + ruleBackendWarning)
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
		res.servicePort.StrVal = backendService.Port.Name
	} else {
		res.servicePort.IntVal = backendService.Port.Number
	}
	return res
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Ingress allowed connections

// PeerAndIngressConnSet captures Peer object as allowed target from ingress-controller Pod, with its possible connections
type PeerAndIngressConnSet struct {
	Peer           eval.Peer
	ConnSet        *common.ConnectionSet
	IngressObjects map[string][]string
}

// AllowedIngressConnections returns a map of the possible connections from ingress-controller pod to workload peers,
// as inferred from Ingress and Route resources. The map is from a workload name to its PeerAndIngressConnSet object.
func (ia *IngressAnalyzer) AllowedIngressConnections() (map[string]*PeerAndIngressConnSet, error) {
	// if there is at least one route/ ingress object that targets a service which selects a dst peer,
	// then we have ingress connections to that peer

	// get all targeted workload peers and compute allowed conns of each workload peer
	// 1. from routes
	routesResult, err := ia.allowedIngressConnectionsByResourcesType(ia.routesToServicesMap, scan.Route)
	if err != nil {
		return nil, err
	}
	// 2. from k8s-ingress objects
	ingressResult, err := ia.allowedIngressConnectionsByResourcesType(ia.k8sIngressToServicesMap, scan.Ingress)
	if err != nil {
		return nil, err
	}

	// merge the map results from routes and k8s-ingress objects
	mergeResults(routesResult, ingressResult)
	return ingressResult, nil
}

// utility func
// mergeResults merges routesMap into ingressMap , since routesMap may be wider with peers connections
func mergeResults(routesMap, ingressMap map[string]*PeerAndIngressConnSet) {
	for k, v := range routesMap {
		if _, ok := ingressMap[k]; ok {
			ingressMap[k].ConnSet.Union(v.ConnSet)
		} else {
			ingressMap[k] = v
		}
	}
}

// allowedIngressConnectionsByResourcesType returns map from peers names to the allowed ingress connections
// based on k8s-Ingress/routes objects rules
func (ia *IngressAnalyzer) allowedIngressConnectionsByResourcesType(mapToIterate map[string]map[string][]serviceInfo, ingType string) (
	map[string]*PeerAndIngressConnSet, error) {
	res := make(map[string]*PeerAndIngressConnSet)
	for ns, objSvcMap := range mapToIterate {
		// if there are no services in same namespace of the Ingress, the ingress objects in this ns will be skipped
		if _, ok := ia.servicesToPortsAndPeersMap[ns]; !ok {
			continue
		}
		for objName, svcList := range objSvcMap {
			ingressObjTargetPeersAndPorts, err := ia.getIngressObjectTargetedPeersAndPorts(ns, svcList)
			if err != nil {
				return nil, err
			}
			// avoid duplicates in the result, consider the different ports supported
			for peer, pConn := range ingressObjTargetPeersAndPorts {
				ingObjStr := types.NamespacedName{Namespace: ns, Name: objName}.String()
				if _, ok := res[peer.String()]; !ok {
					ingressObjs := make(map[string][]string, 2)
					ingressObjs[ingType] = []string{ingObjStr}
					res[peer.String()] = &PeerAndIngressConnSet{Peer: peer, ConnSet: pConn, IngressObjects: ingressObjs}
				} else {
					res[peer.String()].ConnSet.Union(pConn)
					res[peer.String()].IngressObjects[ingType] = append(res[peer.String()].IngressObjects[ingType], ingObjStr)
				}
			}
		}
	}

	return res, nil
}

// getIngressObjectTargetedPeersAndPorts returns map from peers which are targeted by Route/k8s-Ingress objects in their namespace to
// the Ingress required connections
func (ia *IngressAnalyzer) getIngressObjectTargetedPeersAndPorts(ns string,
	svcList []serviceInfo) (map[eval.Peer]*common.ConnectionSet, error) {
	res := make(map[eval.Peer]*common.ConnectionSet)
	for _, svc := range svcList {
		peersAndPorts, ok := ia.servicesToPortsAndPeersMap[ns][svc.serviceName]
		if !ok {
			ia.logger.Warnf("ignoring target service " + svc.serviceName + " : service not found")
		}
		for _, peer := range peersAndPorts.peers {
			currIngressPeerConn, err := ia.getIngressPeerConnection(peer, peersAndPorts.ports, svc.servicePort)
			if err != nil {
				return nil, err
			}
			if _, ok := res[peer]; !ok {
				res[peer] = currIngressPeerConn
			} else {
				res[peer].Union(currIngressPeerConn)
			}
		}
	}
	return res, nil
}

// getIngressPeerConnection returns the ingress connection to a peer based on the required port specified in the ingress objects
func (ia *IngressAnalyzer) getIngressPeerConnection(peer eval.Peer, actualServicePorts []corev1.ServicePort,
	requiredPort intstr.IntOrString) (*common.ConnectionSet, error) {
	peerTCPConn := eval.GetPeerExposedTCPConnections(peer)
	// get the peer port/s which may be accessed by the service required port
	// (if the required port is not specified, all service ports are allowed)
	peerPortsToFind := getPeerAccessPort(actualServicePorts, requiredPort)
	// compute the connection to the peer with the required port/s
	res := common.MakeConnectionSet(false)
	for _, peerPortToFind := range peerPortsToFind {
		portNum := peerPortToFind.IntValue()
		if peerPortToFind.StrVal != "" { // if the port we are searching for is namedPort
			portInt, err := ia.pe.ConvertPeerNamedPort(peerPortToFind.StrVal, peer)
			if err != nil {
				return nil, err
			}
			portNum = int(portInt)
		}

		if peerTCPConn.Contains(strconv.Itoa(portNum), string(corev1.ProtocolTCP)) {
			permittedPort := common.PortSet{}
			permittedPort.AddPort(intstr.FromInt(portNum))
			res.AddConnection(corev1.ProtocolTCP, permittedPort)
		}
	}
	return res, nil
}

// getPeerAccessPort returns the peer's port to be exposed based on the service's port.targetPort value
func getPeerAccessPort(actualServicePorts []corev1.ServicePort, requiredPort intstr.IntOrString) []intstr.IntOrString {
	res := make([]intstr.IntOrString, 0)
	requiredPortEmpty := false // if the required port is empty , then all service's target ports will be used (required)
	if requiredPort.IntVal == 0 && requiredPort.StrVal == "" {
		requiredPortEmpty = true
	}

	// get the peer port/s to find from the required port
	for _, svcPort := range actualServicePorts {
		var svcPodAccessPort intstr.IntOrString
		// extracting the pod access port from the service port
		if !(svcPort.TargetPort.IntVal == 0 && svcPort.TargetPort.StrVal == "") {
			// servicePort.TargetPort is Number or name of the port to access on the pods targeted by the service.
			svcPodAccessPort = svcPort.TargetPort
		} else {
			// if servicePort.TargetPort is not specified, the value of the 'port' field is used
			svcPodAccessPort.IntVal = svcPort.Port
		}

		switch requiredPortEmpty {
		case false: // the required port is specified (not empty)
			// checking if the service port matches the required port, if yes returning its pod access port
			if svcPort.Name != "" && svcPort.Name == requiredPort.StrVal || svcPort.Port == requiredPort.IntVal ||
				svcPort.TargetPort == requiredPort {
				res = append(res, svcPodAccessPort)
				return res
			}
		case true:
			res = append(res, svcPodAccessPort)
		}
	}
	return res
}