/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package k8s

import (
	"fmt"

	apisv1a "sigs.k8s.io/network-policy-api/apis/v1alpha1"

	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
)

// BaselineAdminNetworkPolicy  is an alias for k8s BaselineAdminNetworkPolicy object
type BaselineAdminNetworkPolicy apisv1a.BaselineAdminNetworkPolicy

// Selects returns true if the baseline admin network policy's Spec.Subject selects the peer and if
// the required direction is in the policy spec
func (banp *BaselineAdminNetworkPolicy) Selects(p Peer, isIngress bool) (bool, error) {
	if p.PeerType() == IPBlockType {
		// baselineAdminNetworkPolicy is a cluster level resource which selects peers with their namespaceSelectors and podSelectors only,
		// so it might not select IPs
		return false, nil
	}
	if !banp.baselineAdminPolicyAffectsDirection(isIngress) {
		return false, nil
	}
	// check if the subject selects the given peer
	return subjectSelectsPeer(banp.Spec.Subject, p)
}

// baselineAdminPolicyAffectsDirection returns whether the banp affects the given direction or not.
// banp affects a direction, if its spec has rules on that direction
func (banp *BaselineAdminNetworkPolicy) baselineAdminPolicyAffectsDirection(isIngress bool) bool {
	if isIngress {
		return len(banp.Spec.Ingress) > 0
	}
	return len(banp.Spec.Egress) > 0
}

// banpRuleErr returns string format of an err in a rule in baseline-admin netpol
func banpRuleErr(ruleName, description string) error {
	return fmt.Errorf("default baseline admin network policy: %s %q: %s", ruleErrTitle, ruleName, description)
}

// GetEgressPolicyConns returns the connections from the egress rules selecting the dst in spec of the baselineAdminNetworkPolicy
//
//nolint:dupl // this loops Egress spec - different types
func (banp *BaselineAdminNetworkPolicy) GetEgressPolicyConns(dst Peer) (*PolicyConnections, error) {
	res := InitEmptyPolicyConnections()
	for _, rule := range banp.Spec.Egress {
		rulePeers := rule.To
		if len(rulePeers) == 0 {
			return nil, banpRuleErr(rule.Name, netpolerrors.ANPEgressRulePeersErr)
		}
		rulePorts := rule.Ports
		peerSelected, err := egressRuleSelectsPeer(rulePeers, dst)
		if err != nil {
			return nil, banpRuleErr(rule.Name, err.Error())
		}
		if !peerSelected {
			continue
		}

		ruleConns, err := ruleConnections(rulePorts, dst)
		if err != nil {
			return nil, banpRuleErr(rule.Name, err.Error())
		}
		err = res.UpdateWithRuleConns(ruleConns, string(rule.Action))
		if err != nil {
			return nil, banpRuleErr(rule.Name, err.Error())
		}
	}
	return res, nil
}

// GetIngressPolicyConns returns the connections from the ingress rules selecting the src in spec of the baselineAdminNetworkPolicy
//
//nolint:dupl // this loops Ingress spec - different types
func (banp *BaselineAdminNetworkPolicy) GetIngressPolicyConns(src, dst Peer) (*PolicyConnections, error) {
	res := InitEmptyPolicyConnections()
	for _, rule := range banp.Spec.Ingress {
		rulePeers := rule.From
		if len(rulePeers) == 0 {
			return nil, banpRuleErr(rule.Name, netpolerrors.ANPIngressRulePeersErr)
		}
		rulePorts := rule.Ports
		peerSelected, err := ingressRuleSelectsPeer(rulePeers, src)
		if err != nil {
			return nil, banpRuleErr(rule.Name, err.Error())
		}
		if !peerSelected {
			continue
		}

		ruleConns, err := ruleConnections(rulePorts, dst)
		if err != nil {
			return nil, banpRuleErr(rule.Name, err.Error())
		}
		err = res.UpdateWithRuleConns(ruleConns, string(rule.Action))
		if err != nil {
			return nil, banpRuleErr(rule.Name, err.Error())
		}
	}
	return res, nil
}
