/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package eval

import (
	"errors"

	netv1 "k8s.io/api/networking/v1"

	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval/internal/k8s"
)

// this file contains methods for checking wether specific connection between two peers is allowed or not;
// those funcs are related to the `eval` command

// checkIfAllowedNew: (connection-set based computation) returns true if the given input connection is
// allowed by network policies
// currently used only for testing
func (pe *PolicyEngine) checkIfAllowedNew(src, dst, protocol, port string) (bool, error) {
	allowedConns, err := pe.allAllowedConnections(src, dst)
	if err != nil {
		return false, err
	}
	return allowedConns.Contains(port, protocol), nil
}

// CheckIfAllowed returns true if the given input connection is allowed by k8s: admin-network-policies,
// network-policies and the baseline-admin-network-policy
func (pe *PolicyEngine) CheckIfAllowed(src, dst, protocol, port string) (bool, error) {
	srcPeer, err := pe.getPeer(src)
	if err != nil {
		return false, err
	}
	dstPeer, err := pe.getPeer(dst)
	if err != nil {
		return false, err
	}
	// cases where any connection is always allowed
	if isPodToItself(srcPeer, dstPeer) || isPeerNodeIP(srcPeer, dstPeer) || isPeerNodeIP(dstPeer, srcPeer) {
		return true, nil
	}

	hasResult, res := pe.cache.hasConnectionResult(srcPeer, dstPeer, protocol, port)
	if hasResult {
		return res, nil
	}

	egressRes, err := pe.allowedXgressConnection(srcPeer, dstPeer, false, protocol, port)
	if err != nil {
		return false, err
	}
	if !egressRes {
		pe.cache.addConnectionResult(srcPeer, dstPeer, protocol, port, false)
		return false, nil
	}
	ingressRes, err := pe.allowedXgressConnection(srcPeer, dstPeer, true, protocol, port)
	if err != nil {
		return false, err
	}
	pe.cache.addConnectionResult(srcPeer, dstPeer, protocol, port, ingressRes)
	return ingressRes, nil
}

// allowedXgressConnection returns if the given input connection is allowed on the given ingress/egress direction
// by k8s policies api
func (pe *PolicyEngine) allowedXgressConnection(src, dst k8s.Peer, isIngress bool, protocol, port string) (bool, error) {
	// first checks if the connection is allowed or denied by the admin-network-policies (return anpRes).
	// if the connection is passed by the ANPs or not captured by them, then will continue to NPs (pass = true)
	anpRes, pass, err := pe.allowedXgressConnectionByAdminNetpols(src, dst, isIngress, protocol, port)
	if err != nil {
		return false, err
	}
	if !pass { // i.e the connection is captured by the adminNetworkPolicies and definitely is either allowed or denied
		pe.cache.addConnectionResult(src, dst, protocol, port, anpRes)
		return anpRes, nil
	}
	// else pass == true : means that:
	// - the admin-network-policies did not capture the connection (if the ANPs rules did not capture the connection explicitly,
	// then it is not captured.)
	// - or that the rules captured the connection with action: pass; so it will be determined with netpols/ banp.
	netpolRes, captured, err := pe.allowedXgressConnectionByNetpols(src, dst, isIngress, protocol, port)
	if err != nil {
		return false, err
	}
	// if the src/dst was captured by the relevant xgress policies, then the connection is
	// definitely allowed or denied by the policy rules (either explicitly or implicitly)
	if captured {
		pe.cache.addConnectionResult(src, dst, protocol, port, netpolRes)
		return netpolRes, nil
	}
	// else !captured : means that the xgress connection will be determined by the baseline-admin-network-policy,
	// or the system-default for connection that was not captured by any policy which is allowed.
	defaultRes, err := pe.allowedXgressByBaselineAdminNetpolOrByDefault(src, dst, isIngress, protocol, port)
	if err != nil {
		return false, err
	}
	pe.cache.addConnectionResult(src, dst, protocol, port, defaultRes)
	return defaultRes, nil
}

// allowedXgressConnectionByAdminNetpols returns if the given input connection is allowed on the given ingress/egress direction
// by k8s admin-network-policies
func (pe *PolicyEngine) allowedXgressConnectionByAdminNetpols(src, dst k8s.Peer, isIngress bool, protocol, port string) (res, pass bool,
	err error) {
	// iterate sorted by priority admin netpols
	for _, anp := range pe.sortedAdminNetpols {
		if isIngress {
			selectsDst, err := anp.Selects(dst, true)
			if err != nil {
				return false, false, err
			}
			if selectsDst {
				res, captured, err := anp.CheckIngressConnAllowed(src, dst, protocol, port)
				if err != nil {
					return false, false, err
				}
				if !captured {
					continue // continue to next ANP
				}
				return analyzeANPCapturedRes(res)
			}
		} else { // egress
			selectsSrc, err := anp.Selects(src, false)
			if err != nil {
				return false, false, err
			}
			if selectsSrc {
				res, captured, err := anp.CheckEgressConnAllowed(dst, protocol, port)
				if err != nil {
					return false, false, err
				}
				if !captured {
					continue // continue to next ANP
				}
				return analyzeANPCapturedRes(res)
			}
		}
	}
	// getting here means the connection was not captured by any ANP - pass to netpols
	return false, true, nil
}

// analyzeANPCapturedRes when an admin-network-policy captures a connection , its result may be Allow (final- allowed conn),
// or Deny (final - denied conn) or Pass (to be determined by netpol/ banp)
func analyzeANPCapturedRes(anpRes int) (allowedOrDenied, pass bool, err error) {
	switch anpRes {
	case k8s.Pass:
		return false, true, nil
	case k8s.Allow:
		return true, false, nil
	case k8s.Deny:
		return false, false, nil
	}
	return false, false, errors.New(netpolerrors.UnknownRuleActionErr) // will not get here
}

// allowedXgressConnectionByNetpols returns true if the given connection from src to dst on given direction(ingress/egress)
// is allowed by network policies rules
func (pe *PolicyEngine) allowedXgressConnectionByNetpols(src, dst k8s.Peer, isIngress bool, protocol, port string) (res, captured bool,
	err error) {
	// relevant policies: policies that capture dst if isIngress, else policies that capture src
	var netpols []*k8s.NetworkPolicy
	if isIngress {
		netpols, err = pe.getPoliciesSelectingPod(dst, netv1.PolicyTypeIngress)
	} else {
		netpols, err = pe.getPoliciesSelectingPod(src, netv1.PolicyTypeEgress)
	}
	if err != nil {
		return false, false, err
	}

	if len(netpols) == 0 { // no networkPolicy captures the relevant pod on the required direction
		return false, false, nil // result will be determined later by banp / system-default
	}

	// iterate relevant network policies (that capture the required pod)
	for _, policy := range netpols {
		// if isIngress: check for ingress rules that capture src within 'from'
		// if not isIngress: check for egress rules that capture dst within 'to'
		if isIngress {
			res, err := policy.IngressAllowedConn(src, protocol, port, dst)
			if err != nil {
				return false, false, err
			}
			if res {
				return true, true, nil
			}
		} else {
			res, err := policy.EgressAllowedConn(dst, protocol, port)
			if err != nil {
				return false, false, err
			}
			if res {
				return true, true, nil
			}
		}
	}
	// the src/dst was captured by policies but the given connection is not allowed (so it is implicitly denied)
	return false, true, nil
}

// allowedXgressByBaselineAdminNetpolOrByDefault returns if the given input connection is allowed on the given ingress/egress direction
// by k8s baseline-admin-network-policy; if not captured by the BANP, then returns true as system-default
func (pe *PolicyEngine) allowedXgressByBaselineAdminNetpolOrByDefault(src, dst k8s.Peer, isIngress bool, protocol,
	port string) (bool, error) {
	if pe.baselineAdminNetpol == nil {
		return true, nil // system-default : any non-captured conn is allowed
	}
	if isIngress {
		selectsDst, err := pe.baselineAdminNetpol.Selects(dst, true)
		if err != nil {
			return false, err
		}
		if selectsDst {
			res, captured, err := pe.baselineAdminNetpol.CheckIngressConnAllowed(src, dst, protocol, port)
			if err != nil {
				return false, err
			}
			if !captured {
				return true, nil // system-default
			}
			return analyzeBANPCapturedRes(res)
		}
	} else {
		selectsSrc, err := pe.baselineAdminNetpol.Selects(src, false)
		if err != nil {
			return false, err
		}
		if selectsSrc {
			res, captured, err := pe.baselineAdminNetpol.CheckEgressConnAllowed(dst, protocol, port)
			if err != nil {
				return false, err
			}
			if !captured {
				return true, nil // system-default
			}
			return analyzeBANPCapturedRes(res)
		}
	}
	return true, nil // default
}

// analyzeBANPCapturedRes when a baseline-admin-network-policy captures a connection , its result may be Allow or Deny
func analyzeBANPCapturedRes(res int) (allowedOrDenied bool, err error) {
	switch res {
	case k8s.Allow:
		return true, nil
	case k8s.Deny:
		return false, nil
	}
	return false, errors.New(netpolerrors.UnknownRuleActionErr) // will not get here
}
