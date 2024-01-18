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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval/internal/k8s"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// this file contains eval.PolicyEngine funcs which are related to exposure-analysis feature

// addPotentiallyExposedPods adds pods which are potentially exposed to connect with (from/to) existing pods in the resources
func (pe *PolicyEngine) addPotentiallyExposedPods() error {
	// first adds a pod that represent connections with any namespace
	_, err := pe.AddPodByNameAndNamespace(common.PodInRepNs, common.AllNamespaces, nil)
	if err != nil {
		return err
	}
	// scan policies's rules : generate fake-exposure pod for rules with no match in the resources
	for _, nsNetpolsMap := range pe.netpolsMap {
		for pName, policy := range nsNetpolsMap {
			// scan and handle policy rules which doesn't have a match in the resources
			err = pe.addPodsForUnmatchedRules(pName, policy)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (pe *PolicyEngine) addPodsForUnmatchedRules(policyName string, policy *k8s.NetworkPolicy) error {
	// gets the namespaceSelector-s from policy's rules which contain only namespaceSelector
	namespacesOnly := policy.GetRulesSelectors()
	// find if there are matches for the namespacesSelectors in pe.namespacesMap; if not add relevant pods
	err := pe.addPodsForUnmatchedNamespaceSelectors(namespacesOnly, policyName)
	// TODO : add pods for unmatched rules with:  only podSelector (in the policy's ns)
	// - namespaceSelector + podSelector
	return err
}

// gets a list of policy xgress rules consisted only from namespaceSelector.
// adds new pod for each selector that does not have a matching namespace in the resources
func (pe *PolicyEngine) addPodsForUnmatchedNamespaceSelectors(nsSelectors []*metav1.LabelSelector, policyName string) error {
	for i, selector := range nsSelectors {
		selectorMap, err := metav1.LabelSelectorAsMap(selector)
		if err != nil {
			return err
		}
		foundNs := pe.checkNamespaceSelectorsMatch(selectorMap)
		if !foundNs {
			_, err = pe.AddPodByNameAndNamespace(common.PodInRepNs, common.NsNamePrefix+policyName+fmt.Sprint(i), selectorMap)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// getting a selector , checks if there is a namespace with labels containing all the selector's labels
func (pe *PolicyEngine) checkNamespaceSelectorsMatch(reqSelector map[string]string) bool {
	for _, ns := range pe.namspacesMap {
		cnt := 0
		// check if the selectors of the namespace contain the given selectors
		for sel, val := range reqSelector {
			if ns.Labels[sel] == val {
				cnt++
			}
		}
		if len(reqSelector) == cnt {
			return true
		}
	}
	return false
}

// /////////////////////////////////

// IsPeerProtected returns if the peer is protected by network policies on the given ingress/egress direction
// relevant only for workloadPeer
func (pe *PolicyEngine) IsPeerProtected(p Peer, isIngress bool) (bool, error) {
	peer, ok := p.(*k8s.WorkloadPeer)
	if !ok { // should not get here
		return false, errors.New(netpolerrors.NotPeerErrStr(p.String()))
	}
	if isIngress {
		return peer.Pod.IngressProtected, nil
	}
	return peer.Pod.EgressProtected, nil
}

// TODO these functions will be changed in a later PR (when implementing RepresentativePeer)
func (pe *PolicyEngine) GetPeerNsLabels(p Peer) map[string]string {
	peer := p.(*k8s.WorkloadPeer)
	return peer.Pod.ExposureNsLabels
}
