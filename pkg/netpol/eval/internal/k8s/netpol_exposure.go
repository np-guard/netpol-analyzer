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
package k8s

import (
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// this file contains network-policy funcs that are relevant for exposure analysis

// returns the rules' selectors arranged by type : namespacesOnly - for rules containing only namespaceSelector
// TODO : return (may should save) also results from rules containing only podSelector or
// rules containing both podSelector and namespaceSelector
func (np *NetworkPolicy) GetRulesSelectors() (namespacesOnly []*metav1.LabelSelector) {
	policyPeersRules := []netv1.NetworkPolicyPeer{}
	// getting all NetworkPolicyPeer from the policy (from both ingress and egress)
	for i := range np.Spec.Ingress {
		policyPeersRules = append(policyPeersRules, np.Spec.Ingress[i].From...)
	}
	for i := range np.Spec.Egress {
		policyPeersRules = append(policyPeersRules, np.Spec.Egress[i].To...)
	}
	// scan the rules , append selectors from rules containing only
	for i := range policyPeersRules {
		// assume correctness - TODO - add rule correctness check
		if policyPeersRules[i].IPBlock == nil && policyPeersRules[i].PodSelector == nil &&
			policyPeersRules[i].NamespaceSelector != nil {
			namespacesOnly = append(namespacesOnly, policyPeersRules[i].NamespaceSelector)
		}
	}
	return namespacesOnly
}
