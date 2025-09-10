/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package k8s

import (
	"fmt"
	"strings"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/np-guard/models/pkg/netset"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/alerts"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// this file contains funcs which are commonly used by different policy objects

const (
	portBase    = 10
	portBits    = 32
	egressName  = "Egress"
	ingressName = "Ingress"
)

func getProtocolStr(p *v1.Protocol) string {
	if p == nil || string(*p) == "" { // If not specified, this field defaults to TCP.
		return string(v1.ProtocolTCP)
	}
	return string(*p)
}

// getPortsRange given a rule port and dest peer, returns: the start and end port numbers,
// or the port name if it is a named port
// if input port is a named port, and the dst peer is nil or does not have a matching named port defined, returns
// an empty range represented by (-1,-1) with the named port string
func getPortsRange(port *intstr.IntOrString, protocol *v1.Protocol, endPort *int32, dst Peer, policyName string) (start, end int64,
	portName string, err error) {
	if port.Type == intstr.String { // rule.Port is namedPort
		if endPort != nil { // endPort field may not be defined with named port
			return start, end, "", netpolErr(policyName, alerts.NamedPortErrTitle, alerts.EndPortWithNamedPortErrStr)
		}
		ruleProtocol := getProtocolStr(protocol)
		portName = port.StrVal
		if dst == nil {
			// dst is nil, so the namedPort can not be converted, return string port name
			return common.NoPort, common.NoPort, portName, nil
		}
		if dst.PeerType() != PodType {
			// namedPort is not defined for IP-blocks
			return start, end, "", netpolErr(policyName, alerts.NamedPortErrTitle, alerts.ConvertNamedPortErrStr)
		}
		podProtocol, podPortNum := dst.GetPeerPod().ConvertPodNamedPort(portName)
		if podProtocol == "" && podPortNum == common.NoPort {
			// there is no match for the namedPort in the configuration of the pod, return the portName string as "ports range"
			return common.NoPort, common.NoPort, portName, nil
		}
		if podProtocol != ruleProtocol {
			// the pod has a matching namedPort, but not on same protocol as the rule's protocol; so it can not be converted,
			// return the string named-port as the "ports range"
			return common.NoPort, common.NoPort, portName, nil
		}
		// else, found match for the rule's named-port in the pod's ports, so it may be converted to port number
		start = int64(podPortNum)
		end = int64(podPortNum)
	} else { // rule.Port is number
		start = int64(port.IntVal)
		end = start
		if endPort != nil {
			end = int64(*endPort)
		}
	}
	return start, end, portName, nil
}

func isEmptyPortRange(start, end int64) bool {
	// an empty range when:
	// - end is smaller than start
	// - end or start is not in the legal range (a legal port is 1-65535)
	return (start < common.MinPort || end < common.MinPort) ||
		(end < start) ||
		(start > common.MaxPort || end > common.MaxPort)
}

// doesRulePortContain gets protocol and port numbers of a rule and other protocol and port;
// returns if other is contained in the rule's port
func doesRulePortContain(ruleProtocol, otherProtocol string, ruleStartPort, ruleEndPort, otherPort int64) bool {
	if !strings.EqualFold(ruleProtocol, otherProtocol) {
		return false
	}
	if isEmptyPortRange(ruleStartPort, ruleEndPort) {
		return false
	}
	if otherPort >= ruleStartPort && otherPort <= ruleEndPort {
		return true
	}
	return false
}

// isPeerRepresentative  determines if the peer's source is representativePeer; i.e. its pod fake and has RepresentativePodName
func isPeerRepresentative(peer Peer) bool {
	if peer.GetPeerPod() == nil {
		return false
	}
	return peer.GetPeerPod().IsPodRepresentative()
}

func checkSelectorsMatchForPeer(nsSelector, podSelector *metav1.LabelSelector, peer Peer, policyNs string) (match bool, err error) {
	if peer.PeerType() == IPBlockType {
		return false, nil // assuming that peer of type IP cannot be selected by ns and pod selector
	}
	// peer is a pod
	nsSelMatch := false
	if nsSelector == nil {
		nsSelMatch = (policyNs == peer.GetPeerPod().Namespace)
	} else { // namespaceSelector is not nil
		nsSelMatch, err = doesNamespaceSelectorMatchesPeer(nsSelector, peer)
		if err != nil {
			return false, err
		}
	}
	if !nsSelMatch { // namespace selector does not match - no need to check podSelector too
		return false, nil
	}
	// getting here means nsSelMatch is true - lets check podSelector's match for the peer
	if podSelector == nil {
		return true, nil
	}
	return selectorsMatch(podSelector, peer.GetPeerPod().RepresentativePodLabelSelector,
		peer.GetPeerPod().Labels, isPeerRepresentative(peer))
}

// doesNamespaceSelectorMatchesPeer returns true if the given namespaces LabelSelector matches the given peer's namespace object
func doesNamespaceSelectorMatchesPeer(namespaces *metav1.LabelSelector, peer Peer) (bool, error) {
	if peer.PeerType() == IPBlockType {
		return false, nil // IPs are not namespace-scoped
	}
	peerNamespace := peer.GetPeerNamespace()
	var peerNsLabels map[string]string
	if peerNamespace != nil { // peerNamespace may be nil for representative peers
		peerNsLabels = peerNamespace.Labels
	}
	return selectorsMatch(namespaces, peer.GetPeerPod().RepresentativeNsLabelSelector, peerNsLabels, isPeerRepresentative(peer))
}

// selectorsMatch checks if the given selectors match each other.
// called either with namespace-selectors, or with pod-selectors
// when exposure analysis is on : checks the match between rule selector and the relevant representativePeer selector
// otherwise, checks match between rule-selector and pod/namespace labels
func selectorsMatch(ruleSelector, peerSelector *metav1.LabelSelector, peerLabels map[string]string,
	isPeerRepresentative bool) (selectorsMatch bool, err error) {
	// for exposure analysis (representative-peer), use relevant func to check if representative peer is matched by rule's selector
	if isPeerRepresentative {
		// representative peer is inferred from a rule:
		// - by having representative selector pointing to same reference of the rule's selector
		// - or by having representative labelSelector with requirements equal to the rule's requirements
		// note that if the given ruleSelector is nil, we don't get here.
		return SelectorsFullMatch(ruleSelector, peerSelector)
	} // else for real peer just check if the selector matches the peer's labels
	selector, err := metav1.LabelSelectorAsSelector(ruleSelector)
	if err != nil {
		return false, fmt.Errorf("%s", alerts.SelectorErrTitle+" : "+err.Error())
	}
	return selector.Matches(labels.Set(peerLabels)), nil
}

func parseNetpolCIDR(cidr, policyName string, except []string) (*netset.IPBlock, error) {
	ipb, err := netset.IPBlockFromCidr(cidr)
	if err != nil {
		return nil, netpolErr(policyName, alerts.CidrErrTitle, err.Error())
	}
	ipb, err = ipb.ExceptCidrs(except...)
	if err != nil {
		return nil, netpolErr(policyName, alerts.CidrErrTitle, err.Error())
	}
	return ipb, nil
}

const (
	capturedButNotSelectedExpl   = "selects %s, but %s is not allowed by any %s rule"
	noMatchExplFormat            = "%s selects %s, and %s selects %s, %s"
	noXgressRulesExpl            = capturedButNotSelectedExpl + " (no rules defined)"
	explNoMatchOfNamedPortsToDst = "but named ports of the rule have no match in the configuration of the destination peer"
)

// ConstPeerString returns pod's owner-name not the peer instance name unless it is ip-block (used for explanation)
func ConstPeerString(peer Peer) string {
	peerStr := peer.String()
	if peer.PeerType() != IPBlockType {
		peerStr = (&WorkloadPeer{peer.GetPeerPod()}).String()
	}
	return peerStr
}

func directionName(isIngress bool) string {
	if isIngress {
		return ingressName
	}
	return egressName
}

func notSelectedByRuleExpl(isIngress bool, policyName, expl, policyPeerStr, rulePeerStr string) string {
	return fmt.Sprintf("%s "+expl, policyName, policyPeerStr, rulePeerStr, directionName(isIngress))
}

func capturedPeersButUnmatchedConnsExpl(policyName, ruleName, policyPeerStr, rulePeerStr string) string {
	return fmt.Sprintf(noMatchExplFormat, policyName, policyPeerStr, ruleName, rulePeerStr,
		common.ExplNotReferencedProtocolsOrPorts)
}

func capturedPeersButUnmatchedNamedPortExpl(policyName, ruleName, policyPeerStr, rulePeerStr string) string {
	return fmt.Sprintf(noMatchExplFormat, policyName, policyPeerStr, ruleName, rulePeerStr, explNoMatchOfNamedPortsToDst)
}

func allowedByRuleExpl(policyName, ruleName string) string {
	return fmt.Sprintf("%s allows connections by %s", policyName, ruleName)
}

func netpolErr(policyName, title, description string) error {
	return fmt.Errorf("%s %s: %s", policyName, title, description)
}

func ruleName(ruleIdx int, isIngress bool) string {
	return fmt.Sprintf("%s rule #%d", directionName(isIngress), ruleIdx+1)
}
