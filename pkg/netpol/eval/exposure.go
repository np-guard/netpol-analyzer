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
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/labels"

	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval/internal/k8s"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// this file contains eval.PolicyEngine funcs which are related to exposure-analysis feature

// any fake namespace added will start with following prefix for ns name and following pod name
const repNsNamePrefix = "representative-namespace-"

// generateRepresentativePeers : generates and adds to policy engine representative peers where each peer
// has namespace and pod labels inferred from single policy rule labels in the given list of selectors;
// for example, if a rule within policy has namespaceSelector "foo: managed", then a representative pod in such a
// namespace with those labels will be added, representing all potential pods in such a namespace.
// generated representative peers are unique; i.e. if different rules (e.g in different policies or different directions) has same labels :
// one representative peer is generated to represent both
func (pe *PolicyEngine) generateRepresentativePeers(selectorsLabels []k8s.SingleRuleLabels, policyName string) error {
	for i := range selectorsLabels {
		_, err := pe.AddPodByNameAndNamespace(k8s.RepresentativePodName, repNsNamePrefix+policyName+fmt.Sprint(i), &selectorsLabels[i])
		if err != nil {
			return err
		}
	}
	return nil
}

const comma = ","

// getSortedLabelsString returns a sorted string of the given labels  - helping func
// @todo on podSelector PR : add also sorted podSelector labels to the returned value (for the map key)
func getSortedLabelsString(selectorLabels *k8s.SingleRuleLabels) string {
	nsSelectorStr := labels.SelectorFromSet(labels.Set(selectorLabels.NsLabels)).String()
	selectorSlice := strings.Split(nsSelectorStr, comma)
	sort.Strings(selectorSlice)
	return strings.Join(selectorSlice, comma)
}

// refineRepresentativePeersMatchingLabels removes from the policy engine all representative peers
// with labels matching the given labels of a real pod
func (pe *PolicyEngine) refineRepresentativePeersMatchingLabels(realPodLabels, realNsLabels map[string]string) {
	keysToDelete := make([]string, 0)
	// look for representative peers with labels matching the given real pod's (and its namespace) labels
	for key, peer := range pe.representativePeersMap {
		potentialPodSelector := labels.SelectorFromSet(labels.Set(peer.Pod.Labels))
		potentialNsSelector := labels.SelectorFromSet(labels.Set(peer.PotentialNamespaceLabels))
		if potentialPodSelector.Matches(labels.Set(realPodLabels)) && potentialNsSelector.Matches(labels.Set(realNsLabels)) {
			keysToDelete = append(keysToDelete, key)
		}
	}

	// delete redundant representative peers
	for _, k := range keysToDelete {
		delete(pe.representativePeersMap, k)
	}
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
