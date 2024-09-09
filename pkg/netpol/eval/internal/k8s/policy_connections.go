/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package k8s

import (
	"fmt"

	apisv1a "sigs.k8s.io/network-policy-api/apis/v1alpha1"

	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// PolicyConnections : stores connections between two peers which is collected mainly from admin-network-policies and adjusted with
// connections from network-policies/ baseline-admin-network-policies or system-default allowed connections as following:
// - PASS connections will be enforced by allowed connections from network-policies, or if not captured by network-policies,
// by connections from baseline-admin-network-policies or system-default connections.
// - traffic that has no match in admin-network-policies will be determined also by network-policies or if not captured by network-policies,
// by baseline-admin-network-policies or system default.
type PolicyConnections struct {
	// AllowedConns allowed connections-set between two peers
	AllowedConns *common.ConnectionSet
	// PassConns connections between two peers that was passed by admin-network-policy to policies with lower priority
	// (network-policies/ baseline-admin-network-policies)
	PassConns *common.ConnectionSet
	// DeniedConns denied connections between two peers
	DeniedConns *common.ConnectionSet
}

// InitEmptyPolicyConnections - returns a new PolicyConnections object with empty connection-sets
func InitEmptyPolicyConnections() *PolicyConnections {
	return &PolicyConnections{
		AllowedConns: common.MakeConnectionSet(false),
		DeniedConns:  common.MakeConnectionSet(false),
		PassConns:    common.MakeConnectionSet(false),
	}
}

// UpdateWithRuleConns updates current policy conns with connections from a new rule in same (base)admin-network-policy;
// connections from previous rules are with higher precedence.
func (pc *PolicyConnections) UpdateWithRuleConns(ruleConns *common.ConnectionSet, ruleAction string, banpRules bool) error {
	// banpRules indicates if the rules are coming from BANP; flag used to check the rule Actions are valid since:
	// Unlike AdminNetworkPolicies that enable: "Pass, Deny or Allow" as the action of each rule.
	// BaselineAdminNetworkPolicies allows only "Allow and Deny" as the action of each rule.
	switch ruleAction {
	case string(apisv1a.AdminNetworkPolicyRuleActionAllow):
		ruleConns.Subtract(pc.DeniedConns)
		ruleConns.Subtract(pc.PassConns)
		pc.AllowedConns.Union(ruleConns)
	case string(apisv1a.AdminNetworkPolicyRuleActionDeny):
		ruleConns.Subtract(pc.AllowedConns)
		ruleConns.Subtract(pc.PassConns)
		pc.DeniedConns.Union(ruleConns)
	case string(apisv1a.AdminNetworkPolicyRuleActionPass):
		if banpRules {
			return fmt.Errorf(netpolerrors.UnknownRuleActionErr)
		}
		ruleConns.Subtract(pc.AllowedConns)
		ruleConns.Subtract(pc.DeniedConns)
		pc.PassConns.Union(ruleConns)
	default:
		return fmt.Errorf(netpolerrors.UnknownRuleActionErr)
	}
	return nil
}

// CollectANPConns updates the current policyConnections with given conns object from a new admin-network-policy.
// admin-network-policies are looped by priority order (from lower to higher) , so previous conns take precedence on the conns
// from the new admin-network-policy
func (pc *PolicyConnections) CollectANPConns(newAdminPolicyConns *PolicyConnections) {
	// keep all connections collected from policies with a higher precedence
	newAdminPolicyConns.DeniedConns.Subtract(pc.AllowedConns)
	newAdminPolicyConns.DeniedConns.Subtract(pc.PassConns)
	newAdminPolicyConns.AllowedConns.Subtract(pc.DeniedConns)
	newAdminPolicyConns.AllowedConns.Subtract(pc.PassConns)
	newAdminPolicyConns.PassConns.Subtract(pc.DeniedConns)
	newAdminPolicyConns.PassConns.Subtract(pc.AllowedConns)
	// add the new conns from current policy to the connections from the policies with higher precedence
	pc.DeniedConns.Union(newAdminPolicyConns.DeniedConns)
	pc.AllowedConns.Union(newAdminPolicyConns.AllowedConns)
	pc.PassConns.Union(newAdminPolicyConns.PassConns)
}

// CollectConnsFromLowerPolicyType updates current PolicyConnections object with connections from a
// policy with lower priority than ANP. (e.g. network-policy or baseline-admin-network-policy or instead system-default connection)
// allowed and denied connections of current PolicyConnections object (admin-network-policy) are non-overridden.
// but pass connections in current PolicyConnections object will be determined by the input PolicyConnections parameter.
// note that: passConns in otherConns will always be empty. (np and banp don't contain pass connections)
func (pc *PolicyConnections) CollectConnsFromLowerPolicyType(otherConns *PolicyConnections) {
	// allowed and denied conns of current pc are non-overridden
	otherConns.AllowedConns.Subtract(pc.DeniedConns)
	otherConns.DeniedConns.Subtract(pc.AllowedConns)
	// PASS conns are determined by otherConns
	// find intersection of current pass connections with otherConns's allowedConns and deniedConns
	passAllowCopy := pc.PassConns.Copy() // using a copy since Intersection changes the object, but we want to keep also
	// non-intersected conns
	passAllowCopy.Intersection(otherConns.AllowedConns) // pass conns to be allowed
	passDenyCopy := pc.PassConns.Copy()
	passDenyCopy.Intersection(otherConns.DeniedConns) // pass conns to be denied
	// update current's allowed and denied conns with:
	// 1. determined pass conns
	// 2. with traffic that had no match in ANP (or higher priority policies)
	pc.AllowedConns.Union(passAllowCopy)
	pc.AllowedConns.Union(otherConns.AllowedConns)
	pc.DeniedConns.Union(passDenyCopy)
	pc.DeniedConns.Union(otherConns.DeniedConns)
	// subtract pass-deny and pass-allow from the current Pass conns;
	// note that the updated pc conns may still have non-empty Pass connections (intersection with allow and deny are not full)
	// - this will not affect evaluated netpols conns, as the allowed conns of netpols implicitly deny other conns.
	// - this should be considered with banp - so remaining pass conns will get system default.
	pc.PassConns.Subtract(passAllowCopy)
	pc.PassConns.Subtract(passDenyCopy)
}

// IsEmpty : returns if all connection sets in current policy-connections are empty
func (pc *PolicyConnections) IsEmpty() bool {
	return pc.AllowedConns.IsEmpty() && pc.DeniedConns.IsEmpty() && pc.PassConns.IsEmpty()
}
