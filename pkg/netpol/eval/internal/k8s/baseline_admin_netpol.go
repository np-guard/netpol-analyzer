/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package k8s

import (
	"fmt"

	"github.com/np-guard/models/pkg/netset"

	"github.com/np-guard/netpol-analyzer/pkg/logger"

	apisv1a "sigs.k8s.io/network-policy-api/apis/v1alpha1"
)

// BaselineAdminNetworkPolicy  is an alias for k8s BaselineAdminNetworkPolicy object
type BaselineAdminNetworkPolicy struct {
	*apisv1a.BaselineAdminNetworkPolicy // embedding k8s BaselineAdminNetworkPolicy object
	Logger                              logger.Logger
}

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
		// BANPs with no ingress rules do not affect ingress traffic.
		return len(banp.Spec.Ingress) > 0
	}
	// BANPs with no egress rules do not affect egress traffic.
	return len(banp.Spec.Egress) > 0
}

const banpErrWarnFormat = "default baseline admin network policy: %s in rule %q: %s"

// banpRuleErr returns string format of an err in a rule in baseline-admin netpol
func banpRuleErr(ruleName, description string) error {
	return fmt.Errorf(banpErrWarnFormat, ruleErrTitle, ruleName, description)
}

// banpRuleWarning logs a warning message for a specific banp rule.
func (banp *BaselineAdminNetworkPolicy) banpRuleWarning(ruleName, warning string) {
	banp.Logger.Warnf(banpErrWarnFormat, ruleWarningTitle, ruleName, warning)
}

// logWarnings logs warnings of a given ruleName.
func (banp *BaselineAdminNetworkPolicy) logWarnings(ruleName string) {
	for _, warning := range warnings {
		banp.banpRuleWarning(ruleName, warning)
	}
}

// GetEgressPolicyConns returns the connections from the egress rules selecting the dst in spec of the baselineAdminNetworkPolicy
func (banp *BaselineAdminNetworkPolicy) GetEgressPolicyConns(dst Peer) (*PolicyConnections, error) {
	res := NewPolicyConnections()
	for _, rule := range banp.Spec.Egress { // rule is apisv1a.BaselineAdminNetworkPolicyEgressRule
		rulePeers := rule.To
		rulePorts := rule.Ports
		warnings = []string{} // clear warnings (for each rule) to be update while looping rule peers in next call
		err := updateConnsIfEgressRuleSelectsPeer(rulePeers, rulePorts, dst, res, string(rule.Action), true)
		banp.logWarnings(rule.Name)
		if err != nil {
			return nil, banpRuleErr(rule.Name, err.Error())
		}
	}
	return res, nil
}

// GetIngressPolicyConns returns the connections from the ingress rules selecting the src in spec of the baselineAdminNetworkPolicy
func (banp *BaselineAdminNetworkPolicy) GetIngressPolicyConns(src, dst Peer) (*PolicyConnections, error) {
	res := NewPolicyConnections()
	for _, rule := range banp.Spec.Ingress { // rule is apisv1a.BaselineAdminNetworkPolicyIngressRule
		rulePeers := rule.From
		rulePorts := rule.Ports
		warnings = []string{} // clear warnings (for each rule) to be update while looping rule peers in next call
		err := updateConnsIfIngressRuleSelectsPeer(rulePeers, rulePorts, src, dst, res, string(rule.Action), true)
		banp.logWarnings(rule.Name)
		if err != nil {
			return nil, banpRuleErr(rule.Name, err.Error())
		}
	}
	return res, nil
}

// GetReferencedIPBlocks returns a list of IPBlocks referenced by the BaselineAdminNetworkPolicy's Egress rules.
func (banp *BaselineAdminNetworkPolicy) GetReferencedIPBlocks() ([]*netset.IPBlock, error) {
	res := []*netset.IPBlock{}
	// in BANP only egress rules may contain ip addresses
	for _, rule := range banp.Spec.Egress {
		ruleRes, err := rulePeersReferencedNetworks(rule.To)
		if err != nil {
			return nil, err
		}
		res = append(res, ruleRes...)
	}
	return res, nil
}
