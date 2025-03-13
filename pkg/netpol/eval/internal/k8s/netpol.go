/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package k8s

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/np-guard/models/pkg/netset"

	"github.com/np-guard/netpol-analyzer/pkg/logger"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/alerts"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// @todo is there another preprocessed form of the object that would make more sense?
//
//	for example, converting Spec.PodSelector to labels.Selector on initialization
//	or preprocessing namespaces and pods that match selector in ingress/egress rules, etc
//
// -> might help to pre-process and store peers that match policy selectors + selectors in rules + set of allowed connections per rule
type NetworkPolicy struct {
	*netv1.NetworkPolicy // embedding k8s network policy object
	// following data stored in preprocessing when exposure-analysis is on;
	// storing the cluster wide exposure of the policy on both ingress and egress directions;
	// those connections are inferred when the policy has no rules, or from empty rules.
	// note that : when there are no rules in the policy, the pod is actually exposed to entire cluster and all external IP, however the
	// external exposure is not stored here since we use IP-Block Peers as the external peers when computing allowed connections,
	// and those conns are also attached to exposure-analysis output.

	// IngressPolicyClusterWideExposure contains:
	// - the maximal connection-set which the policy's rules allow from all namespaces in the cluster on ingress direction
	// those conns are inferred when the policy has no rules, or from empty rules.
	IngressPolicyClusterWideExposure *PolicyConnections
	// EgressPolicyClusterWideExposure contains:
	// - the maximal connection-set which the policy's rules allow to all namespaces in the cluster on egress direction
	// those conns are inferred when the policy has no rules, or from empty rules.
	EgressPolicyClusterWideExposure *PolicyConnections
	warnings                        common.Warnings // set of warnings which are raised by the netpol
}

// @todo might help if while pre-process, to check containment of all rules' connections; if all "specific" rules
// connections are contained in the "general" rules connections, then we can avoid iterating policy rules for computing
// connections between two peers

// @todo need a network policy collection type along with convenience methods?
// 	if so, also consider concurrent access (or declare not goroutine safe?)

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
func (np *NetworkPolicy) getPortsRange(rulePort netv1.NetworkPolicyPort, dst Peer) (start, end int64,
	portName string, err error) {
	if rulePort.Port.Type == intstr.String { // rule.Port is namedPort
		if rulePort.EndPort != nil { // endPort field may not be defined with named port
			return start, end, "", np.netpolErr(alerts.NamedPortErrTitle, alerts.EndPortWithNamedPortErrStr)
		}
		ruleProtocol := getProtocolStr(rulePort.Protocol)
		portName = rulePort.Port.StrVal
		if dst == nil {
			// dst is nil, so the namedPort can not be converted, return string port name
			return common.NoPort, common.NoPort, portName, nil
		}
		if dst.PeerType() != PodType {
			// namedPort is not defined for IP-blocks
			return start, end, "", np.netpolErr(alerts.NamedPortErrTitle, alerts.ConvertNamedPortErrStr)
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
		start = int64(rulePort.Port.IntVal)
		end = start
		if rulePort.EndPort != nil {
			end = int64(*rulePort.EndPort)
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

func (np *NetworkPolicy) rulePeersAndPorts(ruleIdx int, isIngress bool) ([]netv1.NetworkPolicyPeer, []netv1.NetworkPolicyPort) {
	if isIngress {
		return np.Spec.Ingress[ruleIdx].From, np.Spec.Ingress[ruleIdx].Ports
	}
	return np.Spec.Egress[ruleIdx].To, np.Spec.Egress[ruleIdx].Ports
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

func (np *NetworkPolicy) ruleConnections(rulePorts []netv1.NetworkPolicyPort, dst Peer,
	ruleIdx int, isIngress bool, policyPeerStr, rulePeerStr string) (*common.ConnectionSet, error) {
	if len(rulePorts) == 0 {
		// If this field is empty or missing, this rule matches all ports
		// (traffic not restricted by port)
		return common.MakeConnectionSetWithRule(true, common.NPRuleKind, np.allowedByRuleExpl(np.ruleName(ruleIdx, isIngress)), isIngress), nil
	}
	ruleName := np.ruleName(ruleIdx, isIngress)
	// all protocols are affected by the rule
	res := common.MakeConnectionSetWithRule(false, common.NPRuleKind,
		np.capturedPeersButUnmatchedConnsExpl(ruleName, policyPeerStr, rulePeerStr), isIngress)
	for i := range rulePorts {
		protocol := v1.ProtocolTCP
		if rulePorts[i].Protocol != nil {
			protocol = *rulePorts[i].Protocol
		}
		// the whole port range is affected by the rule (not only ports mentioned in the rule)
		ports := common.MakeEmptyPortSetWithImplyingRules(
			common.MakeImplyingRulesWithRule(common.NPRuleKind,
				np.capturedPeersButUnmatchedConnsExpl(ruleName, policyPeerStr, rulePeerStr), isIngress))
		if rulePorts[i].Port == nil {
			ports = common.MakeAllPortSetWithImplyingRules(common.MakeImplyingRulesWithRule(common.NPRuleKind,
				np.allowedByRuleExpl(ruleName), isIngress))
		} else {
			startPort, endPort, portName, err := np.getPortsRange(rulePorts[i], dst)
			if err != nil {
				return res, err
			}
			// valid returned values from `getsPortsRange` :
			// 1. empty-numbered-range with the non-empty string namedPort, if the rule has a named-port which is not (or cannot be) converted to a
			// numbered-range by the dst's ports.
			//  2. non empty-range when the rule ports are numbered or the named-port was converted
			if isEmptyPortRange(startPort, endPort) {
				if portName != "" {
					// this func may be called:
					// 1- for computing cluster-wide exposure of the policy (dst is nil);
					// 2- in-order to get a connection from a real workload to a representative dst.
					// in both first cases, we can't convert the named port to its number, like when dst peer is a real
					// pod from manifests, so we use the named-port as is.
					// 3- in order to get a connection from any pod to a real dst.
					// in the third case the namedPort of the policy rule may not have a match in the Pod's configuration,
					// so it will be ignored and a warning is raised
					// (the pod has no matching named-port in its configuration - unknown connection is not allowed)
					// 4- in order to get a connection from any pod to an ip dst (will not get here, as named ports are not defined for ip-blocks)
					if dst == nil || isPeerRepresentative(dst) { // (1 & 2)
						// adding portName string to the portSet
						ports.AddPort(intstr.FromString(portName), common.MakeImplyingRulesWithRule(common.NPRuleKind,
							np.allowedByRuleExpl(ruleName), isIngress))
					} else { // dst is a real pod (3)
						// add a warning that the "named port" of the rule is ignored, since it has no match in the pod config.
						np.saveNetpolWarning(np.netpolWarning(alerts.WarnUnmatchedNamedPort(portName, dst.String())))
					}
				} else { // empty port range with empty port name -> means the range is illegal (start/ end not in the legal range or end < start)
					return nil, errors.New(alerts.IllegalPortRangeError(startPort, endPort))
				}
			} else {
				// if !isEmptyPortRange(startPort, endPort) (the other valid result)
				ports.AddPortRange(startPort, endPort, true, common.NPRuleKind, np.allowedByRuleExpl(ruleName), isIngress)
			}
		}
		res.AddConnection(protocol, ports)
	}
	if res.IsEmpty() {
		// no connections found --> "named ports" of the rule had no match in the pod config
		// remove empty protocols if any
		res = common.MakeConnectionSetWithRule(false, common.NPRuleKind,
			np.capturedPeersButUnmatchedNamedPortExpl(ruleName, policyPeerStr, rulePeerStr), isIngress)
	}
	return res, nil
}

// isPeerRepresentative  determines if the peer's source is representativePeer; i.e. its pod fake and has RepresentativePodName
func isPeerRepresentative(peer Peer) bool {
	if peer.GetPeerPod() == nil {
		return false
	}
	return peer.GetPeerPod().IsPodRepresentative()
}

func (np *NetworkPolicy) saveNetpolWarning(warning string) {
	if np.warnings == nil {
		np.warnings = make(map[string]bool)
	}
	np.warnings.AddWarning(warning)
}

// ruleConnsContain returns true if the given protocol and port are contained in connections allowed by rulePorts
func (np *NetworkPolicy) ruleConnsContain(rulePorts []netv1.NetworkPolicyPort, protocol, port string, dst Peer) (bool, error) {
	if len(rulePorts) == 0 {
		return true, nil // If this field is empty or missing, this rule matches all ports (traffic not restricted by port)
	}
	if protocol == "" && port == "" {
		return false, nil // nothing to do
	}
	intPort, err := strconv.ParseInt(port, portBase, portBits)
	if err != nil {
		return false, err
	}
	for i := range rulePorts {
		if rulePorts[i].Port == nil { // If this field is not provided, this matches all port names and numbers.
			return true, nil
		}
		startPort, endPort, portName, err := np.getPortsRange(rulePorts[i], dst)
		if err != nil {
			return false, err
		}
		if isEmptyPortRange(startPort, endPort) {
			if portName != "" { // there is a port that was not converted, raise a warning
				np.saveNetpolWarning(np.netpolWarning(alerts.WarnUnmatchedNamedPort(portName, dst.String())))
			} else { // the policy contains an error : illegal port range
				return false, errors.New(alerts.IllegalPortRangeError(startPort, endPort))
			}
		}
		if doesRulePortContain(getProtocolStr(rulePorts[i].Protocol), protocol,
			startPort, endPort, intPort) {
			return true, nil
		}
	}
	return false, nil
}

// ruleSelectsPeer returns true if the given peer is in the set of peers selected by rulePeers
//
//gocyclo:ignore
func (np *NetworkPolicy) ruleSelectsPeer(rulePeers []netv1.NetworkPolicyPeer, peer Peer) (bool, error) {
	if len(rulePeers) == 0 {
		return true, nil // If this field is empty or missing, this rule matches all destinations
	}
	for i := range rulePeers {
		if rulePeers[i].PodSelector == nil && rulePeers[i].NamespaceSelector == nil && rulePeers[i].IPBlock == nil {
			return false, np.netpolErr(alerts.RulePeerErrTitle, alerts.EmptyRulePeerErrStr)
		}
		if rulePeers[i].PodSelector != nil || rulePeers[i].NamespaceSelector != nil {
			if rulePeers[i].IPBlock != nil {
				return false, np.netpolErr(alerts.RulePeerErrTitle, alerts.CombinedRulePeerErrStr)
			}
			if peer.PeerType() == IPBlockType {
				continue // assuming that peer of type IP cannot be selected by pod selector
			}
			// peer is a pod
			peerMatchesPodSelector := false
			peerMatchesNamespaceSelector := false
			var err error
			if rulePeers[i].NamespaceSelector == nil {
				peerMatchesNamespaceSelector = (np.ObjectMeta.Namespace == peer.GetPeerPod().Namespace)
			} else { // namespaceSelector is not nil
				peerMatchesNamespaceSelector, err = doesNamespaceSelectorMatchesPeer(rulePeers[i].NamespaceSelector, peer)
				if err != nil {
					return false, err
				}
			}
			if !peerMatchesNamespaceSelector {
				continue // skip to next peerObj
			}
			if rulePeers[i].PodSelector == nil {
				peerMatchesPodSelector = true
			} else {
				peerMatchesPodSelector, err = selectorsMatch(rulePeers[i].PodSelector, peer.GetPeerPod().RepresentativePodLabelSelector,
					peer.GetPeerPod().Labels, isPeerRepresentative(peer))
				if err != nil {
					return false, err
				}
			}
			if peerMatchesPodSelector {
				return true, nil //  matching both pod selector and ns_selector here
			}
		} else { // ipblock
			if peer.PeerType() == PodType {
				continue // assuming that peer of type Pod cannot be selected by IPBlock
				// TODO: is this reasonable to assume?
			}
			// check that peer.IP matches the IPBlock
			ruleIPBlock, err := np.parseNetpolCIDR(rulePeers[i].IPBlock.CIDR, rulePeers[i].IPBlock.Except)
			if err != nil {
				return false, err
			}
			if peer.GetPeerIPBlock().IsSubset(ruleIPBlock) {
				return true, nil
			}
		}
	}
	return false, nil
}

// IngressAllowedConn returns true  if the given connections from src to any of the pods captured by the policy is allowed
func (np *NetworkPolicy) IngressAllowedConn(src Peer, protocol, port string, dst Peer) (bool, error) {
	// iterate list of rules: []NetworkPolicyIngressRule
	for i := range np.Spec.Ingress {
		rulePeers := np.Spec.Ingress[i].From
		rulePorts := np.Spec.Ingress[i].Ports

		peerSelected, err := np.ruleSelectsPeer(rulePeers, src)
		if err != nil {
			return false, err
		}
		if !peerSelected {
			continue
		}
		connSelected, err := np.ruleConnsContain(rulePorts, protocol, port, dst)
		if err != nil {
			return false, err
		}
		if connSelected {
			return true, nil
		}
	}
	return false, nil
}

// EgressAllowedConn returns true if the given connection to dst from any of the pods captured by the policy is allowed
func (np *NetworkPolicy) EgressAllowedConn(dst Peer, protocol, port string) (bool, error) {
	for i := range np.Spec.Egress {
		rulePeers := np.Spec.Egress[i].To
		rulePorts := np.Spec.Egress[i].Ports

		peerSelected, err := np.ruleSelectsPeer(rulePeers, dst)
		if err != nil {
			return false, err
		}
		if !peerSelected {
			continue
		}
		connSelected, err := np.ruleConnsContain(rulePorts, protocol, port, dst)
		if err != nil {
			return false, err
		}
		if connSelected {
			return true, nil
		}
	}
	return false, nil
}

const (
	capturedButNotSelectedExpl   = "selects %s, but %s is not allowed by any %s rule"
	noMatchExplFormat            = "%s selects %s, and %s selects %s, %s"
	noXgressRulesExpl            = capturedButNotSelectedExpl + " (no rules defined)"
	explNoMatchOfNamedPortsToDst = "but named ports of the rule have no match in the configuration of the destination peer"
)

// constPeerString returns pod's owner-name not the peer instance name unless it is ip-block (used for explanation)
func constPeerString(peer Peer) string {
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

func (np *NetworkPolicy) notSelectedByRuleExpl(isIngress bool, expl, policyPeerStr, rulePeerStr string) string {
	return fmt.Sprintf("%s "+expl, np.FullName(), policyPeerStr, rulePeerStr, directionName(isIngress))
}

func (np *NetworkPolicy) capturedPeersButUnmatchedConnsExpl(ruleName, policyPeerStr, rulePeerStr string) string {
	return fmt.Sprintf(noMatchExplFormat, np.FullName(), policyPeerStr, ruleName, rulePeerStr,
		common.ExplNotReferencedProtocolsOrPorts)
}

func (np *NetworkPolicy) capturedPeersButUnmatchedNamedPortExpl(ruleName, policyPeerStr, rulePeerStr string) string {
	return fmt.Sprintf(noMatchExplFormat, np.FullName(), policyPeerStr, ruleName, rulePeerStr, explNoMatchOfNamedPortsToDst)
}

func (np *NetworkPolicy) allowedByRuleExpl(ruleName string) string {
	return fmt.Sprintf("%s allows connections by %s", np.FullName(), ruleName)
}

// GetXgressAllowedConns returns the set of allowed connections to a captured dst pod from the src peer (for Ingress)
// or from any captured pod to the dst peer (for Egress)
func (np *NetworkPolicy) GetXgressAllowedConns(src, dst Peer, isIngress bool) (*common.ConnectionSet, error) {
	res := common.MakeConnectionSet(false)
	numOfRules := len(np.Spec.Egress)
	peerToSelect := dst // the peer to check if selected by policy rules
	policyPeer := src   // the peer captured by the policy
	if isIngress {
		numOfRules = len(np.Spec.Ingress)
		peerToSelect = src
		policyPeer = dst
	}
	policyPeerStr := constPeerString(policyPeer)
	peerToSelectStr := constPeerString(peerToSelect)
	if numOfRules == 0 {
		res.AddCommonImplyingRule(common.NPRuleKind, np.notSelectedByRuleExpl(isIngress, noXgressRulesExpl,
			policyPeerStr, peerToSelectStr), isIngress)
		return res, nil
	}
	peerSelectedByAnyRule := false
	for idx := 0; idx < numOfRules; idx++ {
		rulePeers, rulePorts := np.rulePeersAndPorts(idx, isIngress)
		peerSelected, err := np.ruleSelectsPeer(rulePeers, peerToSelect)
		if err != nil {
			return res, err
		}
		if !peerSelected {
			continue
		}
		peerSelectedByAnyRule = true
		// sending policyPeerStr and peerToSelectStr for explanation goals
		ruleConns, err := np.ruleConnections(rulePorts, dst, idx, isIngress, policyPeerStr, peerToSelectStr)
		if err != nil {
			return res, err
		}
		res.Union(ruleConns, false)
		if res.AllowAll {
			return res, nil
		}
	}
	if !peerSelectedByAnyRule {
		res.AddCommonImplyingRule(common.NPRuleKind, np.notSelectedByRuleExpl(isIngress, capturedButNotSelectedExpl,
			policyPeerStr, peerToSelectStr), isIngress)
	}
	return res, nil
}

func (np *NetworkPolicy) netpolWarning(description string) string {
	return fmt.Sprintf("%s: %s", np.FullName(), description)
}

func (np *NetworkPolicy) netpolErr(title, description string) error {
	return fmt.Errorf("%s %s: %s", np.FullName(), title, description)
}

func (np *NetworkPolicy) parseNetpolCIDR(cidr string, except []string) (*netset.IPBlock, error) {
	ipb, err := netset.IPBlockFromCidr(cidr)
	if err != nil {
		return nil, np.netpolErr(alerts.CidrErrTitle, err.Error())
	}
	ipb, err = ipb.ExceptCidrs(except...)
	if err != nil {
		return nil, np.netpolErr(alerts.CidrErrTitle, err.Error())
	}
	return ipb, nil
}

func (np *NetworkPolicy) parseNetpolLabelSelector(selector *metav1.LabelSelector) (labels.Selector, error) {
	selectorRes, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return nil, np.netpolErr(alerts.SelectorErrTitle, err.Error())
	}
	return selectorRes, nil
}

func (np *NetworkPolicy) rulePeersReferencedIPBlocks(rulePeers []netv1.NetworkPolicyPeer) ([]*netset.IPBlock, error) {
	res := []*netset.IPBlock{}
	for _, peerObj := range rulePeers {
		if peerObj.IPBlock != nil {
			ipb, err := np.parseNetpolCIDR(peerObj.IPBlock.CIDR, peerObj.IPBlock.Except)
			if err != nil {
				return nil, err
			}
			res = append(res, ipb.Split()...)
		}
	}
	return res, nil
}

// GetReferencedIPBlocks: return lists of src and dst IPBlock objects referenced in the current network policy
func (np *NetworkPolicy) GetReferencedIPBlocks() (srcIpbList, dstIpbList []*netset.IPBlock, err error) {
	for _, rule := range np.Spec.Ingress {
		ruleRes, err := np.rulePeersReferencedIPBlocks(rule.From)
		if err != nil {
			return nil, nil, err
		}
		srcIpbList = append(srcIpbList, ruleRes...)
	}
	for _, rule := range np.Spec.Egress {
		ruleRes, err := np.rulePeersReferencedIPBlocks(rule.To)
		if err != nil {
			return nil, nil, err
		}
		dstIpbList = append(dstIpbList, ruleRes...)
	}
	return srcIpbList, dstIpbList, nil
}

// policyAffectsDirection receives ingress/egress direction and returns true if it affects this direction on its captured pods
func (np *NetworkPolicy) policyAffectsDirection(direction netv1.PolicyType) bool {
	// check if direction (Ingress/Egress) is in np.PolicyTypes [if PolicyTypes was specified]
	if len(np.Spec.PolicyTypes) > 0 {
		for _, affectedDirection := range np.Spec.PolicyTypes {
			if direction == affectedDirection {
				return true
			}
		}
		return false
	} else if direction == netv1.PolicyTypeIngress {
		return true // all policies without defined PolicyTypes are assumed to affect Ingress
	}
	// policy without defined PolicyTypes affects Egress only if it has Egress rules
	return len(np.Spec.Egress) > 0
}

// Selects returns true if the network policy's Spec.PodSelector selects the Pod and if the required direction is in the policy types
func (np *NetworkPolicy) Selects(p *Pod, direction netv1.PolicyType) (bool, error) {
	//  @todo check namespace matching here? -> namespace should match
	if p.Namespace != np.Namespace {
		return false, nil
	}

	if !np.policyAffectsDirection(direction) {
		return false, nil
	}
	// currently ignoring policies which select representative peers, as exposure analysis goal is
	// to hint where a policy selecting real workloads can be tightened
	if p.IsPodRepresentative() {
		return false, nil
	}

	//  @todo check if the empty selector is handled by Matches() below
	if len(np.Spec.PodSelector.MatchLabels) == 0 && len(np.Spec.PodSelector.MatchExpressions) == 0 {
		return true, nil //  empty selector matches all pods
	}

	selector, err := np.parseNetpolLabelSelector(&np.Spec.PodSelector)
	if err != nil {
		return false, err
	}
	return selector.Matches(labels.Set(p.Labels)), nil
}

func (np *NetworkPolicy) FullName() string {
	return fmt.Sprintf("NetworkPolicy '%s'", types.NamespacedName{Name: np.Name, Namespace: np.Namespace}.String())
}

func (np *NetworkPolicy) ruleName(ruleIdx int, isIngress bool) string {
	return fmt.Sprintf("%s rule #%d", directionName(isIngress), ruleIdx+1)
}

func (np *NetworkPolicy) LogWarnings(l logger.Logger) {
	np.warnings.LogPolicyWarnings(l)
}

// /////////////////////////////////////////////////////////////////////////////////////////////
// pre-processing computations - currently performed for exposure-analysis goals only;
// all pre-process funcs assume policies' rules are legal (rules correctness check occurs later)

// SingleRuleSelectors contains LabelSelector objects representing namespaceSelector or/and podSelector
// of a single rule in the policy
type SingleRuleSelectors struct {
	NsSelector  *metav1.LabelSelector
	PodSelector *metav1.LabelSelector
}

func (s SingleRuleSelectors) isEmpty() bool {
	return s.NsSelector == nil && s.PodSelector == nil
}

// GetPolicyRulesSelectorsAndUpdateExposureClusterWideConns scans policy rules and :
// - updates policy's exposed cluster-wide connections from/to all namespaces in the cluster on ingress and egress directions
// - returns list of labels.selectors from rules which have non-empty selectors, for which the representative peers should be generated
func (np *NetworkPolicy) GetPolicyRulesSelectorsAndUpdateExposureClusterWideConns() (rulesSelectors []SingleRuleSelectors, err error) {
	if np.policyAffectsDirection(netv1.PolicyTypeIngress) {
		selectors, err := np.scanIngressRules()
		if err != nil {
			return nil, err
		}
		rulesSelectors = append(rulesSelectors, selectors...)
	}
	if np.policyAffectsDirection(netv1.PolicyTypeEgress) {
		selectors, err := np.scanEgressRules()
		if err != nil {
			return nil, err
		}
		rulesSelectors = append(rulesSelectors, selectors...)
	}
	return rulesSelectors, nil
}

// scanIngressRules handles policy's ingress rules (for updating policy's wide conns/ returning specific rules' selectors)
func (np *NetworkPolicy) scanIngressRules() ([]SingleRuleSelectors, error) {
	rulesSelectors := []SingleRuleSelectors{}
	for idx, rule := range np.Spec.Ingress {
		rulePeers := rule.From
		rulePorts := rule.Ports
		selectors, err := np.getSelectorsAndUpdateExposureClusterWideConns(rulePeers, rulePorts, idx, true)
		if err != nil {
			return nil, err
		}
		rulesSelectors = append(rulesSelectors, selectors...)
	}
	return rulesSelectors, nil
}

// scanEgressRules handles policy's egress rules (for updating policy's wide conns/ returning specific rules' selectors)
func (np *NetworkPolicy) scanEgressRules() ([]SingleRuleSelectors, error) {
	rulesSelectors := []SingleRuleSelectors{}
	for idx, rule := range np.Spec.Egress {
		rulePeers := rule.To
		rulePorts := rule.Ports
		selectors, err := np.getSelectorsAndUpdateExposureClusterWideConns(rulePeers, rulePorts, idx, false)
		if err != nil {
			return nil, err
		}
		// rule with selectors selecting specific namespaces/ pods
		rulesSelectors = append(rulesSelectors, selectors...)
	}
	return rulesSelectors, nil
}

// getSelectorsAndUpdateExposureClusterWideConns:
// loops given rules list:
// - if the rules list is empty updates the cluster wide exposure of the policy
// - if a rule have empty selectors (podSelector and namespaceSelector)or just empty namespaceSelector (nil podSelector)
// updates the cluster wide exposure of the policy
// - if a rule contains at least one defined selector : appends the rule selectors to a selector list which will be returned.
// this func assumes rules are legal (rules correctness check occurs later)
func (np *NetworkPolicy) getSelectorsAndUpdateExposureClusterWideConns(rules []netv1.NetworkPolicyPeer, rulePorts []netv1.NetworkPolicyPort,
	ruleIdx int, isIngress bool) (rulesSelectors []SingleRuleSelectors, err error) {
	if len(rules) == 0 {
		err = np.updateNetworkPolicyExposureClusterWideConns(rulePorts, ruleIdx, isIngress)
		return nil, err
	}
	for i := range rules {
		var ruleSel SingleRuleSelectors
		if rules[i].IPBlock != nil {
			continue
		}
		// a rule is exposed to entire cluster if :
		// 1. the podSelector is nil (no podSelector) but the namespaceSelector is empty ({}) not nil
		// 2. both podSelector and namespaceSelector are empty ({})
		// (note that podSelector and namespaceSelector cannot be both nil, this is invalid )
		// if podSelector is not nil but namespaceSelector is nil, this is the netpol's namespace
		if doesRuleSelectAllNamespaces(rules[i].NamespaceSelector, rules[i].PodSelector) {
			err = np.updateNetworkPolicyExposureClusterWideConns(rulePorts, ruleIdx, isIngress)
			return nil, err
		}
		// else selectors' combination specifies workloads by labels (at least one is not nil and not empty)
		ruleSel.PodSelector = rules[i].PodSelector
		ruleSel.NsSelector = rules[i].NamespaceSelector
		rulesSelectors = append(rulesSelectors, ruleSel)
	}
	return rulesSelectors, nil
}

// doesRuleSelectAllNamespaces returns if the rule selects all-namespaces (entire-cluster)
// a rule is exposed to entire cluster if :
// 1. the podSelector is nil (no podSelector) but the namespaceSelector is empty ({}) not nil
// 2. both podSelector and namespaceSelector are empty ({})
// note that podSelector and namespaceSelector cannot be both nil, this is invalid
func doesRuleSelectAllNamespaces(namespaceSelector, podSelector *metav1.LabelSelector) bool {
	return namespaceSelector != nil && namespaceSelector.Size() == 0 && (podSelector == nil || podSelector.Size() == 0)
}

// updateNetworkPolicyExposureClusterWideConns updates the cluster-wide exposure connections of the policy
// note that, since NetworkPolicy rules may contain only allow conns data then, updating the AllowedConns field of the
// ClusterWideExposure objects of the policy
func (np *NetworkPolicy) updateNetworkPolicyExposureClusterWideConns(rulePorts []netv1.NetworkPolicyPort,
	ruleIdx int, isIngress bool) error {
	// sending "" peers strings for last two parameters since this func is used only for exposure, and explanation is
	// not supported with exposure yet
	// @todo : update with policy-peer-str and "entire-cluster" when supporting explanation for exposure
	ruleConns, err := np.ruleConnections(rulePorts, nil, ruleIdx, isIngress, "", "")
	if err != nil {
		return err
	}
	if isIngress {
		np.IngressPolicyClusterWideExposure.AllowedConns.Union(ruleConns, false)
	} else {
		np.EgressPolicyClusterWideExposure.AllowedConns.Union(ruleConns, false)
	}
	return nil
}
