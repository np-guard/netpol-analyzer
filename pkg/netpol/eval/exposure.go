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
package eval

import (
	"errors"
	"fmt"

	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval/internal/k8s"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// this file contains eval.PolicyEngine funcs which are related to exposure-analysis feature

// any fake namespace added will start with following prefix for ns name and following pod name
const repNsNamePrefix = "representative-namespace-"

// generateRepresentativePeers adds representative pods with namespace or pod labels inferred from given selectors
// which are extracted from network policies rules.
// for example, if a rule within policy has namespace selector "name: foo", then a representative pod in such a
// namespace with those labels will be added, representing all potential pods in such a namespace
func (pe *PolicyEngine) generateRepresentativePeers(selectorsLabels []k8s.SingleRuleLabels, policyName string) error {
	for i := range selectorsLabels {
		_, err := pe.AddPodByNameAndNamespace(k8s.RepresentativePodName, repNsNamePrefix+policyName+fmt.Sprint(i), &selectorsLabels[i])
		if err != nil {
			return err
		}
	}
	return nil
}

// /////////////////////////////////

// isPeerAWorkloadPeer checks and returns the peer if it is a k8s workload peer
func isPeerAWorkloadPeer(p Peer) (*k8s.WorkloadPeer, error) {
	peer, ok := p.(*k8s.WorkloadPeer)
	if !ok { // should not get here
		return nil, errors.New(netpolerrors.NotPeerErrStr(p.String()))
	}
	return peer, nil
}

// IsPeerProtected returns if the peer is protected by network policies on the given ingress/egress direction
// relevant only for workloadPeer
func (pe *PolicyEngine) IsPeerProtected(p Peer, isIngress bool) (bool, error) {
	peer, err := isPeerAWorkloadPeer(p)
	if err != nil { // should not get here
		return false, err
	}
	if isIngress {
		return peer.Pod.IngressExposureData.IsProtected, nil
	}
	return peer.Pod.EgressExposureData.IsProtected, nil
}

// GetPeerXgressEntireClusterConn returns the connection to entire cluster on given ingress/egress direction
// relevant only for workloadPeer
func (pe *PolicyEngine) GetPeerXgressEntireClusterConn(p Peer, isIngress bool) (*common.ConnectionSet, error) {
	peer, err := isPeerAWorkloadPeer(p)
	if err != nil { // should not get here
		return nil, err
	}
	if isIngress {
		return peer.Pod.IngressExposureData.EntireClusterConnection, nil
	}
	return peer.Pod.EgressExposureData.EntireClusterConnection, nil
}

/////////////////////////////////////////////

// IsRepresentativePeer returns whether the peer is representative peer (inferred from netpol rule)
func (pe *PolicyEngine) IsRepresentativePeer(peer Peer) bool {
	_, ok := peer.(*k8s.RepresentativePeer)
	return ok
}

// GetPeerNsLabels returns namespace labels defining the given representative peer
// relevant only for RepresentativePeer
func (pe *PolicyEngine) GetPeerNsLabels(p Peer) (map[string]string, error) {
	peer, ok := p.(*k8s.RepresentativePeer)
	if !ok { // should not get here
		return nil, errors.New(netpolerrors.NotRepresentativePeerErrStr(p.String()))
	}
	return peer.PotentialNamespaceLabels, nil
}

// IsRedundantRepresentativePeer returns wether the given peer is a redundant representative peer or not
func (pe *PolicyEngine) IsRedundantRepresentativePeer(peer Peer) bool {
	if !pe.IsRepresentativePeer(peer) {
		return false
	}
	return peer.(*k8s.RepresentativePeer).IsRedundant
}

/////////

// RepresentativePeerMatchesRealWorkloadPeer gets two peers
// if one is a WorkloadPeer and the other is a RepresentativePeer: returns whether the namespaceLabels (TODO: and podLabels)
// of the RepresentativePeer are contained in the labels of the WorkloadPeer's namespace
func (pe *PolicyEngine) RepresentativePeerMatchesRealWorkloadPeer(firstPeer, secondPeer Peer) bool {
	var repPeer *k8s.RepresentativePeer
	var wlPeer *k8s.WorkloadPeer
	if pe.IsRepresentativePeer(firstPeer) {
		repPeer = firstPeer.(*k8s.RepresentativePeer)
		// if the second is not a workload peer - no match for sure ; return false
		if wlPeer, _ = isPeerAWorkloadPeer(secondPeer); wlPeer == nil {
			return false
		}
		// TODO : compare also podLabels
		return pe.potentialNamespaceLabelsContainedInRealLabels(repPeer, wlPeer)
	} // else
	wlPeer, _ = isPeerAWorkloadPeer(firstPeer)
	if !pe.IsRepresentativePeer(secondPeer) || wlPeer == nil {
		return false
	}
	repPeer = secondPeer.(*k8s.RepresentativePeer)
	return pe.potentialNamespaceLabelsContainedInRealLabels(repPeer, wlPeer)
}

// potentialNamespaceLabelsContainedInRealLabels checks if the potential namespaceLabels of the fake peer's namespace are contained in
// the labels of the namespace of the real workloadpeer;
// if yes, mark the representative peer as redundant
func (pe *PolicyEngine) potentialNamespaceLabelsContainedInRealLabels(repPeer *k8s.RepresentativePeer, wlPeer *k8s.WorkloadPeer) bool {
	// todo : special case: add check for namespaceName and the "name" label of fake namespace
	potentialNsLabels := repPeer.PotentialNamespaceLabels
	realPodPeer, _ := pe.convertPeerToPodPeer(wlPeer) // todo: handle err
	actualWlNsLabels := realPodPeer.NamespaceObject.Labels
	if isMapContainedInOther(potentialNsLabels, actualWlNsLabels) {
		repPeer.IsRedundant = true
		return true
	}
	return false
}

func isMapContainedInOther(subMap, other map[string]string) bool {
	if len(subMap) > len(other) {
		return false
	}
	for k, v := range subMap {
		if otherV, ok := other[k]; !ok || v != otherV {
			return false
		}
	}
	return true
}
