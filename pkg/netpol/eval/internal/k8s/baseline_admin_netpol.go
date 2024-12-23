/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package k8s

import (
	"errors"
	"fmt"

	"github.com/np-guard/models/pkg/netset"

	apisv1a "sigs.k8s.io/network-policy-api/apis/v1alpha1"

	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
	"github.com/np-guard/netpol-analyzer/pkg/logger"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// BaselineAdminNetworkPolicy  is an alias for k8s BaselineAdminNetworkPolicy object
type BaselineAdminNetworkPolicy struct {
	*apisv1a.BaselineAdminNetworkPolicy                 // embedding k8s BaselineAdminNetworkPolicy object
	warnings                            common.Warnings // set of warnings which are raised by the banp
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
	return subjectSelectsPeer(banp.Spec.Subject, p, banpErrTitle)
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

const (
	banpErrTitle      = "default baseline admin network policy: "
	banpErrWarnFormat = banpErrTitle + " in rule %q: %s"
)

// banpRuleErr returns string format of an err in a rule in baseline-admin netpol
func banpRuleErr(ruleName, description string) error {
	return fmt.Errorf(banpErrWarnFormat, ruleName, description)
}

// banpRuleWarning returns string format of a warning message for a specific banp rule.
func banpRuleWarning(ruleName, warning string) string {
	return fmt.Sprintf(banpErrWarnFormat, ruleName, warning)
}

// savePolicyWarnings saves any warnings generated for an admin network policy rule in the policy's warnings set.
func (banp *BaselineAdminNetworkPolicy) savePolicyWarnings(ruleName string) {
	if banp.warnings == nil {
		banp.warnings = make(map[string]bool)
	}
	for _, warning := range ruleWarnings {
		banp.warnings.AddWarning(banpRuleWarning(ruleName, warning))
	}
}

func (banp *BaselineAdminNetworkPolicy) fullName() string {
	return "[BANP] " + banp.Name
}

// GetEgressPolicyConns returns the connections from the egress rules selecting the dst in spec of the baselineAdminNetworkPolicy
func (banp *BaselineAdminNetworkPolicy) GetEgressPolicyConns(dst Peer) (*PolicyConnections, error) {
	res := NewPolicyConnections()
	for _, rule := range banp.Spec.Egress { // rule is apisv1a.BaselineAdminNetworkPolicyEgressRule
		rulePeers := rule.To
		rulePorts := rule.Ports
		ruleWarnings = []string{} // clear ruleWarnings (for each rule) to be update while looping rule peers in next call
		err := updateConnsIfEgressRuleSelectsPeer(rulePeers, rulePorts,
			ruleFullName(banp.fullName(), rule.Name, string(rule.Action), false),
			dst, res, string(rule.Action), true)
		banp.savePolicyWarnings(rule.Name)
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
		ruleWarnings = []string{} // clear ruleWarnings (for each rule) to be update while looping rule peers in next call
		err := updateConnsIfIngressRuleSelectsPeer(rulePeers, rulePorts,
			ruleFullName(banp.fullName(), rule.Name, string(rule.Action), true),
			src, dst, res, string(rule.Action), true)
		banp.savePolicyWarnings(rule.Name)
		if err != nil {
			return nil, banpRuleErr(rule.Name, err.Error())
		}
	}
	return res, nil
}

// CheckEgressConnAllowed checks if the input conn is allowed/denied on egress by the baseline-admin-network-policy;
// note that if the baseline-admin-network-policy does not capture the given connection thus it is allowed by default.
func (banp *BaselineAdminNetworkPolicy) CheckEgressConnAllowed(dst Peer, protocol, port string) (res bool, err error) {
	for _, rule := range banp.Spec.Egress {
		rulePeers := rule.To
		rulePorts := rule.Ports
		ruleWarnings = []string{} // clear ruleWarnings (for each rule) to be update while looping rule peers in next call
		res, err := checkIfEgressRuleContainsConn(rulePeers, rulePorts, dst, string(rule.Action), protocol, port, true)
		banp.savePolicyWarnings(rule.Name)
		if err != nil {
			return false, err
		}
		if res == NotCaptured { // next rule
			continue
		}
		return allowedByBANPRules(res)
	}
	// getting here means the protocol+port was not captured thus allowed as system-default
	return true, nil
}

// CheckIngressConnAllowed checks if the input conn is allowed/denied on ingress by the baseline-admin-network-policy;
// note that if the baseline-admin-network-policy does not capture the given connection thus it is allowed by default.
func (banp *BaselineAdminNetworkPolicy) CheckIngressConnAllowed(src, dst Peer, protocol, port string) (res bool, err error) {
	for _, rule := range banp.Spec.Ingress {
		rulePeers := rule.From
		rulePorts := rule.Ports
		ruleWarnings = []string{} // clear ruleWarnings (for each rule) to be update while looping rule peers in next call
		res, err := checkIfIngressRuleContainsConn(rulePeers, rulePorts, src, dst, string(rule.Action), protocol, port, true)
		banp.savePolicyWarnings(rule.Name)
		if err != nil {
			return false, err
		}
		if res == NotCaptured { // next rule
			continue
		}
		return allowedByBANPRules(res)
	}
	// getting here means the protocol+port was not captured thus allowed as system-default
	return true, nil
}

// analyzeBANPCapturedRes when a baseline-admin-network-policy captures a connection , its result may be Allow or Deny
func allowedByBANPRules(res ANPRulesResult) (allowedOrDenied bool, err error) {
	switch res {
	case Allow:
		return true, nil
	case Deny:
		return false, nil
	}
	return false, errors.New(netpolerrors.UnknownRuleActionErr) // will not get here
}

// GetReferencedIPBlocks returns a list of IPBlocks referenced by the BaselineAdminNetworkPolicy's Egress rules.
func (banp *BaselineAdminNetworkPolicy) GetReferencedIPBlocks() ([]*netset.IPBlock, error) {
	res := []*netset.IPBlock{}
	// in BANP only egress rules may contain ip addresses
	for _, rule := range banp.Spec.Egress {
		ruleRes, err := rulePeersReferencedIPBlocks(rule.To)
		if err != nil {
			return nil, err
		}
		res = append(res, ruleRes...)
	}
	return res, nil
}

func (banp *BaselineAdminNetworkPolicy) LogWarnings(l logger.Logger) {
	banp.warnings.LogPolicyWarnings(l)
}
