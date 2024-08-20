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

// PolicyConnections : stores connections collected mainly from admin-network-policies and adjusted with allowed netpols conns
// or default conns
type PolicyConnections struct {
	AllowedConns *common.ConnectionSet
	PassConns    *common.ConnectionSet
	DeniedConns  *common.ConnectionSet
}

func InitEmptyPolicyConnections() *PolicyConnections {
	return &PolicyConnections{
		AllowedConns: common.MakeConnectionSet(false),
		DeniedConns:  common.MakeConnectionSet(false),
		PassConns:    common.MakeConnectionSet(false),
	}
}

// CollectANPConns updates the current policyConnections with given conns from another admin-network-policy
// policies are looped by priority order (from lower to higher) , so previous conns take precedence on the conns
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

// UpdateWithRuleConns updates current policy conns object with connection of a rule in an admin-network-policy
// connections from previous rules are with higher precedence
func (pc *PolicyConnections) UpdateWithRuleConns(ruleConns *common.ConnectionSet, ruleAction apisv1a.AdminNetworkPolicyRuleAction) error {
	switch ruleAction {
	case apisv1a.AdminNetworkPolicyRuleActionAllow:
		ruleConns.Subtract(pc.DeniedConns)
		ruleConns.Subtract(pc.PassConns)
		pc.AllowedConns.Union(ruleConns)
	case apisv1a.AdminNetworkPolicyRuleActionDeny:
		ruleConns.Subtract(pc.AllowedConns)
		ruleConns.Subtract(pc.PassConns)
		pc.DeniedConns.Union(ruleConns)
	case apisv1a.AdminNetworkPolicyRuleActionPass:
		ruleConns.Subtract(pc.AllowedConns)
		ruleConns.Subtract(pc.DeniedConns)
		pc.PassConns.Union(ruleConns)
	default:
		return fmt.Errorf(netpolerrors.UnknownRuleActionErr)
	}
	return nil
}

// UpdateWithOtherLayerConns updates current policy connections object with connections from a
// layer with lower precedence (e.g. netpols conns/default conns)
// ANP allowed and denied conns takes precedence on network-policy conns
// Pass conns from ANP are determined by the NPs conns
// @todo change the input to *PolicyConnections and update the func's code
func (pc *PolicyConnections) UpdateWithOtherLayerConns(otherLayerConns *common.ConnectionSet) {
	otherLayerConns.Subtract(pc.DeniedConns)
	pc.PassConns.Intersection(otherLayerConns)
	pc.AllowedConns.Union(pc.PassConns)
	pc.AllowedConns.Union(otherLayerConns)
}

// IsEmpty : returns if all connection sets in current policy-connections are empty
func (pc *PolicyConnections) IsEmpty() bool {
	return pc.AllowedConns.IsEmpty() && pc.DeniedConns.IsEmpty() && pc.PassConns.IsEmpty()
}
