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
	// PassConns connections-set between two peers that was passed by admin-network-policy;
	// i.e. delegate decision about them to next layer of policies, NetworkPolicies or BaselineAdminNetworkPolicies resources
	PassConns *common.ConnectionSet
	// DeniedConns denied connections between two peers
	DeniedConns *common.ConnectionSet
}

// NewPolicyConnections - returns a new PolicyConnections object with empty connection-sets
func NewPolicyConnections() *PolicyConnections {
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
		pc.AllowedConns.Union(ruleConns, false)
	case string(apisv1a.AdminNetworkPolicyRuleActionDeny):
		ruleConns.Subtract(pc.AllowedConns)
		ruleConns.Subtract(pc.PassConns)
		pc.DeniedConns.Union(ruleConns, false)
	case string(apisv1a.AdminNetworkPolicyRuleActionPass):
		if banpRules {
			return fmt.Errorf(netpolerrors.UnknownRuleActionErr)
		}
		ruleConns.Subtract(pc.AllowedConns)
		ruleConns.Subtract(pc.DeniedConns)
		pc.PassConns.Union(ruleConns, false)
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
	pc.DeniedConns.Union(newAdminPolicyConns.DeniedConns, false)
	pc.AllowedConns.Union(newAdminPolicyConns.AllowedConns, false)
	pc.PassConns.Union(newAdminPolicyConns.PassConns, false)
}

// ComplementPassConns complements pass connections to all connections (by adding the absent conections)
func (pc *PolicyConnections) ComplementPassConns() {
	defaultPassConn := NewPolicyConnections()
	defaultPassConn.PassConns = common.MakeConnectionSet(true)
	pc.CollectANPConns(defaultPassConn)
}

// CollectAllowedConnsFromNetpols updates allowed conns of current PolicyConnections object with allowed connections from
// k8s NetworkPolicy objects.
// Allowed and Denied connections of current PolicyConnections object (admin-network-policy) are non-overridden.
// note that:
// 1. the input connections will include only non-empty allowed conns (since its source is netpols);
// and any connection that is not allowed by the netpols is denied.
// 2. pass connections in current PolicyConnections object will be determined by the input PolicyConnections parameter.
func (pc *PolicyConnections) CollectAllowedConnsFromNetpols(npConns *PolicyConnections) {
	// This Union with PassConn does not have effect on the resulting connectios,
	// but it updates implying rules, representing the effect of PassConn as well
	// We start from PassConn, and union npConns.AllowedConns with it,
	// because the order of Union impacts the order of implying rules.
	newConn := pc.PassConns.Copy()
	newConn.Intersection(npConns.AllowedConns) // collect implying rules from pc.PassConns and npConns.AllowedConns
	// subtract the denied conns (which are non-overridden) from input conns
	newConn.Subtract(pc.DeniedConns)
	// PASS conns are determined by npConns
	// currently, npConns.AllowedConns contains:
	// 1. traffic that was passed by ANPs (if there are such conns)
	// 2. traffic that had no match in ANPs
	// so we can update current allowed conns with them
	// 'false' below: we don't add implying rules from NPs if the connections were defined by ANPs
	pc.AllowedConns.Union(newConn, false)
	// now pc.AllowedConns contains all allowed conns by the ANPs and NPs
	// the content of pc.Denied and pc.Pass is not relevant anymore;
	// all the connections that are not allowed by the ANPs and NPs are denied.
}

// CollectConnsFromBANP updates current PolicyConnections object (which contains collected conns from ANPs)
// with connections from a BANP.
// Allowed and Denied connections of current PolicyConnections object (admin-network-policy) are non-overridden.
// note that:
// 1. passConns of the input connections will always be empty. (may contain non-empty allowed/ denied conns)
// 2. pass connections in current PolicyConnections object will be determined by the input PolicyConnections
// parameter or system-default value.
// 3. since both ANP and BANP rules are read as-is; any connection that is not mentioned in any of the admin-policies
// is allowed by default
func (pc *PolicyConnections) CollectConnsFromBANP(banpConns *PolicyConnections) {
	// allowed and denied conns of current pc are non-overridden

	// This Union with PassConn does not have effect on the resulting connectios,
	// but it updates implying rules, representing the effect of PassConn as well
	// We start from PassConn, and union banpConns.DeniedConns with it,
	// because the order of Union impacts the order of implying rules.
	newDenied := pc.PassConns.Copy()
	newDenied.Intersection(banpConns.DeniedConns) // collect implying rules from pc.PassConns and banpConns.DeniedConns
	newDenied.Subtract(pc.AllowedConns)
	pc.DeniedConns.Union(newDenied, true) // 'true' because denied conns are defined by rules from both sides
	// the allowed conns are "all conns - the denied conns"
	// all conns that are not determined by the ANP and BANP are allowed by default,
	// and are kept in banpConns.AllowedConns (were returned by getXgressDefaultConns)
	newAllowed := pc.PassConns.Copy()
	newAllowed.Intersection(banpConns.AllowedConns) // collect implying rules from pc.PassConns and banpConns.AllowedConns
	pc.AllowedConns.Union(newAllowed, false)        // 'false' because allowed conns may be already defined by pc.AllowedConns

	pc.AllowedConns.Subtract(pc.DeniedConns)
}

// IsEmpty : returns true iff all connection sets in current policy-connections are empty
func (pc *PolicyConnections) IsEmpty() bool {
	return pc.AllowedConns.IsEmpty() && pc.DeniedConns.IsEmpty() && pc.PassConns.IsEmpty()
}

// DeterminesAllConns : returns true if the allowed and denied connections of the current PolicyConnections object
// selects all the connections
func (pc *PolicyConnections) DeterminesAllConns() bool {
	selectedConns := pc.AllowedConns.Copy()
	selectedConns.Union(pc.DeniedConns, false)
	return selectedConns.IsAllConnections()
}
