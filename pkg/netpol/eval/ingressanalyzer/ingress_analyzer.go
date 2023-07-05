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
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval/internal/k8s"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/scan"
)

type (
	IngressAnalyzer struct {
		routesMap map[string]map[string]*k8s.Route // map from namespace to map from route name to its object
		// k8sIngressMap map[string]map[string]*k8s.Ingress // map from namespace to map from ingress name to its object
	}

	// NotificationTarget defines an interface for updating the state needed for ingress
	// decisions
	NotificationTarget interface {
		// UpsertObject inserts (or updates) an object to the policy engine's view of the world
		UpsertObject(obj runtime.Object) error
		// DeleteObject removes an object from the policy engine's view of the world
		DeleteObject(obj runtime.Object) error
	}
)

// NewIngressAnalyzer returns a new IngressAnalyzer with an empty initial state
func NewIngressAnalyzer() *IngressAnalyzer {
	return &IngressAnalyzer{
		routesMap: make(map[string]map[string]*k8s.Route),
	}
}

// NewIngressAnalyzerWithObjects returns a new IngressAnalyzer with relevant objects
func NewIngressAnalyzerWithObjects(objects []scan.K8sObject) (*IngressAnalyzer, error) {
	ia := NewIngressAnalyzer()
	var err error
	for _, obj := range objects {
		if obj.Kind == scan.Route { // todo: when adding more objects (ingress) will rewrite if statement to switch
			err = ia.UpsertObject(obj.Route)
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
		Name:      "ingress-controller",
		Namespace: "",
	}
	return &k8s.WorkloadPeer{Pod: ingressPod}
}

// UpsertObject updates (an existing) or inserts (a new) object in the ingress analyzer
func (ia *IngressAnalyzer) UpsertObject(rtobj runtime.Object) error {
	obj := rtobj.(*ocroutev1.Route)
	// route object
	if obj != nil { // todo: when adding more objects (ingress) will rewrite if statement to switch on rtobj.(type)
		return ia.upsertRoute(obj)
	}
	return nil
}

// DeleteObject removes an object from the ingress analyzer
func (ia *IngressAnalyzer) DeleteObject(rtobj runtime.Object) error {
	obj := rtobj.(*ocroutev1.Route)
	// route object
	if obj != nil { // todo: when adding more objects (ingress) will rewrite if statement to switch on rtobj.(type)
		return ia.deleteRoute(obj)
	}
	return nil
}

// ClearResources: deletes all current ingress resources
func (ia *IngressAnalyzer) ClearResources() {
	ia.routesMap = make(map[string]map[string]*k8s.Route)
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

func (ia *IngressAnalyzer) deleteRoute(rt *ocroutev1.Route) error {
	if rtMap, ok := ia.routesMap[rt.Namespace]; ok {
		delete(rtMap, rt.Name)
		if len(rtMap) == 0 {
			delete(ia.routesMap, rt.Namespace)
		}
	}
	return nil
}

////////////////////////////////////////////////////////////////////////////////////

// AllowedIngressConnectionsToAWorkloadPeer return the allowed external ingress-controller's connections to the dst peer
func (ia *IngressAnalyzer) AllowedIngressConnectionsToAWorkloadPeer(dst eval.Peer, pe *eval.PolicyEngine) (eval.Connection, error) {
	// if there is at least one route/ ingress object that targets a service which selects the dst peer,
	// then we have an ingress conns to the peer

	// assuming dstPeer is WorkloadPeer, should be converted to k8s.Peer
	dstPodPeer, err := pe.ConvertWorkloadPeerToPodPeer(dst)
	if err != nil {
		return nil, err
	}

	peerNs := dstPodPeer.Namespace()
	rtMap, ok := ia.routesMap[peerNs]
	if !ok {
		return nil, nil // no ingress objects in the pod's namespace
	}

	for _, rt := range rtMap {
		if pe.CheckServiceSelectsPod(rt.TargetSvc, peerNs, dstPodPeer.Pod) {
			return eval.GetConnectionObject((dstPodPeer.Pod).AllowedConnectionsToPod()), nil
		}
	}

	return nil, nil // did not find any defined ingress connection to the dst peer
}
