/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package k8s

import (
	"errors"
	"fmt"
	"strings"

	mnpv1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"

	"github.com/np-guard/netpol-analyzer/pkg/logger"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/alerts"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

type MultiNetworkPolicy struct {
	*mnpv1.MultiNetworkPolicy                 //  embedding  k8snetworkplumbingwg MultiNetworkPolicy object
	Warnings                  common.Warnings // set of warnings which are raised by the netpol
}

func (mnp *MultiNetworkPolicy) LogWarnings(l logger.Logger) []string {
	return mnp.Warnings.LogWarnings(l)
}

// k8s.v1.cni.cncf.io/policy-for annotation specifies which net-attach-def is the policy target as comma separated list
const policyForAnnotation = "k8s.v1.cni.cncf.io/policy-for"

// GetMNPXgressAllowedConns returns the set of allowed connections to a captured dst pod from the src peer (for Ingress)
// or from any captured pod to the dst peer (for Egress)
//
//nolint:dupl // even though MultiNetworkPolicy analysis is similar to NetworkPolicy's analysis. those objects
//nolint:dupl // are imported from different packages and thus their fields have different types
func (mnp *MultiNetworkPolicy) GetMNPXgressAllowedConns(src, dst Peer, isIngress bool) (*common.ConnectionSet, error) {
	res := common.MakeConnectionSet(false)
	numOfRules := len(mnp.Spec.Egress)
	peerToSelect := dst // the peer to check if selected by policy rules
	policyPeer := src   // the peer captured by the policy
	if isIngress {
		numOfRules = len(mnp.Spec.Ingress)
		peerToSelect = src
		policyPeer = dst
	}
	policyPeerStr := ConstPeerString(policyPeer)
	peerToSelectStr := ConstPeerString(peerToSelect)
	if numOfRules == 0 {
		res.AddCommonImplyingRule(common.MNPRuleKind, notSelectedByRuleExpl(isIngress, mnp.FullName(), noXgressRulesExpl,
			policyPeerStr, peerToSelectStr), isIngress)
		return res, nil
	}
	peerSelectedByAnyRule := false
	for idx := 0; idx < numOfRules; idx++ {
		rulePeers, rulePorts := mnp.rulePeersAndPorts(idx, isIngress)
		peerSelected, err := mnp.ruleSelectsPeer(rulePeers, peerToSelect)
		if err != nil {
			return res, err
		}
		if !peerSelected {
			continue
		}
		peerSelectedByAnyRule = true
		// sending policyPeerStr and peerToSelectStr for explanation goals
		ruleConns, err := mnp.ruleConnections(rulePorts, dst, idx, isIngress, policyPeerStr, peerToSelectStr)
		if err != nil {
			return res, err
		}
		res.Union(ruleConns, false)
		if res.AllowAll {
			return res, nil
		}
	}
	if !peerSelectedByAnyRule {
		res.AddCommonImplyingRule(common.MNPRuleKind, notSelectedByRuleExpl(isIngress, mnp.FullName(), capturedButNotSelectedExpl,
			policyPeerStr, peerToSelectStr), isIngress)
	}
	return res, nil
}

func (mnp *MultiNetworkPolicy) rulePeersAndPorts(ruleIdx int, isIngress bool) ([]mnpv1.MultiNetworkPolicyPeer,
	[]mnpv1.MultiNetworkPolicyPort) {
	if isIngress {
		return mnp.Spec.Ingress[ruleIdx].From, mnp.Spec.Ingress[ruleIdx].Ports
	}
	return mnp.Spec.Egress[ruleIdx].To, mnp.Spec.Egress[ruleIdx].Ports
}

//gocyclo:ignore
func (mnp *MultiNetworkPolicy) ruleSelectsPeer(rulePeers []mnpv1.MultiNetworkPolicyPeer, peer Peer) (bool, error) {
	if len(rulePeers) == 0 {
		return true, nil // If this field is empty or missing, this rule matches all destinations
	}
	for i := range rulePeers {
		if rulePeers[i].PodSelector == nil && rulePeers[i].NamespaceSelector == nil && rulePeers[i].IPBlock == nil {
			return false, netpolErr(mnp.FullName(), alerts.MNPRulePeerErrTitle, alerts.EmptyRulePeerErrStr)
		}
		if rulePeers[i].PodSelector != nil || rulePeers[i].NamespaceSelector != nil {
			if rulePeers[i].IPBlock != nil {
				return false, netpolErr(mnp.FullName(), alerts.MNPRulePeerErrTitle, alerts.CombinedRulePeerErrStr)
			}
			selectorsMatch, err := checkSelectorsMatchForPeer(rulePeers[i].NamespaceSelector, rulePeers[i].PodSelector, peer, mnp.Namespace)
			if err != nil {
				return false, err
			}
			if !selectorsMatch {
				continue // rule does not match - skip to next rule-peerObj
			}
			return true, nil
		} // else  // ipblock - still not supported, it should check match with the peer's pod IP
		mnp.Warnings.AddWarning(mnp.FullName() + " " + alerts.MNPUnsupportedRuleField)
		return false, nil
	}
	return false, nil
}

func (mnp *MultiNetworkPolicy) ruleConnections(rulePorts []mnpv1.MultiNetworkPolicyPort, dst Peer,
	ruleIdx int, isIngress bool, policyPeerStr, rulePeerStr string) (*common.ConnectionSet, error) {
	if len(rulePorts) == 0 {
		// If this field is empty or missing, this rule matches all ports
		// (traffic not restricted by port)
		return common.MakeConnectionSetWithRule(true, common.MNPRuleKind, allowedByRuleExpl(mnp.FullName(),
			ruleName(ruleIdx, isIngress)), isIngress), nil
	}
	ruleName := ruleName(ruleIdx, isIngress)
	// all protocols are affected by the rule
	res := common.MakeConnectionSetWithRule(false, common.MNPRuleKind,
		capturedPeersButUnmatchedConnsExpl(mnp.FullName(), ruleName, policyPeerStr, rulePeerStr), isIngress)
	for i := range rulePorts {
		protocol := v1.ProtocolTCP
		if rulePorts[i].Protocol != nil {
			protocol = *rulePorts[i].Protocol
		}
		// the whole port range is affected by the rule (not only ports mentioned in the rule)
		ports := common.MakeEmptyPortSetWithImplyingRules(
			common.MakeImplyingRulesWithRule(common.MNPRuleKind,
				capturedPeersButUnmatchedConnsExpl(mnp.FullName(), ruleName, policyPeerStr, rulePeerStr), isIngress))
		if rulePorts[i].Port == nil {
			ports = common.MakeAllPortSetWithImplyingRules(common.MakeImplyingRulesWithRule(common.MNPRuleKind,
				allowedByRuleExpl(mnp.FullName(), ruleName), isIngress))
		} else {
			startPort, endPort, portName, err := getPortsRange(rulePorts[i].Port, rulePorts[i].Protocol, rulePorts[i].EndPort, dst, mnp.FullName())
			if err != nil {
				return res, netpolErr(mnp.FullName(), alerts.NamedPortErrTitle, err.Error())
			}
			if isEmptyPortRange(startPort, endPort) {
				if portName == "" { // empty port range + empty port name means the range was illegal
					return nil, errors.New(alerts.IllegalPortRangeError(startPort, endPort))
				} // else  warn the named-port was not converted (has no match in the pod's configuration)
				mnp.Warnings.AddWarning(mnp.FullName() + " " + alerts.WarnUnmatchedNamedPort(portName, dst.String()))
			} else {
				// if !isEmptyPortRange(startPort, endPort)
				ports.AddPortRange(startPort, endPort, true, common.MNPRuleKind, allowedByRuleExpl(mnp.FullName(), ruleName), isIngress)
			}
		}
		res.AddConnection(protocol, ports)
	}
	if res.IsEmpty() {
		// no connections found --> "named ports" of the rule had no match in the pod config
		// remove empty protocols if any
		res = common.MakeConnectionSetWithRule(false, common.MNPRuleKind,
			capturedPeersButUnmatchedNamedPortExpl(mnp.FullName(), ruleName, policyPeerStr, rulePeerStr), isIngress)
	}
	return res, nil
}

// TargetsNetwork : returns true if the policyFor annotation contains the networkName, and if there is a NAD in same network/policy
// namespace
func (mnp *MultiNetworkPolicy) TargetsNetwork(networkName string, nsSet map[string]bool) (bool, error) {
	contains, ns, err := mnp.isPolicyForRequiredNetwork(networkName)
	if err != nil {
		return false, err
	}
	if !contains {
		return false, nil
	}
	// A NAD with network name must be provided in the network's namespace
	// check that there is a NAD in the network's ns if ns != "" else in the policy's ns
	if ns == "" {
		ns = mnp.Namespace
	}
	return nsSet[ns], nil
}

const comma = ","

func (mnp *MultiNetworkPolicy) isPolicyForRequiredNetwork(networkName string) (contains bool, ns string, err error) {
	policyNetworks := mnp.Annotations[policyForAnnotation]
	if policyNetworks == "" {
		return false, "", netpolErr(mnp.FullName(), alerts.MissingPolicyForAnnotation, alerts.InvalidMultiNetworkPolicyAnnotation)
	}
	for _, net := range strings.Split(policyNetworks, comma) { // policy-for is comma separated list
		name := net
		if strings.Contains(net, string(types.Separator)) {
			name = strings.Split(net, string(types.Separator))[1]
			ns = strings.Split(net, string(types.Separator))[0]
		}
		if name == networkName {
			return true, ns, nil
		}
	}
	return false, "", nil
}

// Selects: returns true if the multi-network policy's Spec.PodSelector selects the Pod and if the required direction is in
// the policy types
func (mnp *MultiNetworkPolicy) Selects(pod *Pod, direction string) (bool, error) {
	if !mnp.multiNetworkPolicyAffectsDirection(direction) {
		return false, nil
	}
	selector, err := metav1.LabelSelectorAsSelector(&mnp.Spec.PodSelector)
	if err != nil {
		return false, netpolErr(mnp.FullName(), alerts.SelectorErrTitle, err.Error())
	}
	return selector.Matches(labels.Set(pod.Labels)), nil
}

func (mnp *MultiNetworkPolicy) multiNetworkPolicyAffectsDirection(direction string) bool {
	if len(mnp.Spec.PolicyTypes) > 0 {
		for _, affectedDirection := range mnp.Spec.PolicyTypes {
			if affectedDirection == mnpv1.MultiPolicyType(direction) {
				return true
			}
		}
		return false
	} else if direction == string(mnpv1.PolicyTypeIngress) {
		return true
	}
	// policy without defined PolicyTypes affects Egress only if it has Egress rules
	return len(mnp.Spec.Egress) > 0
}

func (mnp *MultiNetworkPolicy) FullName() string {
	return fmt.Sprintf("MultiNetworkPolicy '%s'", types.NamespacedName{Name: mnp.Name, Namespace: mnp.Namespace}.String())
}
