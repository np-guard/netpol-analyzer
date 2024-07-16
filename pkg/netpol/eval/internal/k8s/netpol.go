/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package k8s

import (
	"fmt"
	"strconv"
	"strings"

	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/np-guard/models/pkg/ipblock"

	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// @todo is there another preprocessed form of the object that would make more sense?
//
//	for example, converting Spec.PodSelector to labels.Selector on initialization
//	or preprocessing namespaces and pods that match selector in ingress/egress rules, etc
//
// -> might help to preprocess and store peers that match policy selectors + selectors in rules + set of allowed connections per rule
type NetworkPolicy struct {
	*netv1.NetworkPolicy // embedding k8s network policy object
	// following data stored in preprocessing when exposure-analysis is on;
	// IngressGeneralConns contains:
	// - the maximal connection-set which the policy's rules allow to all destinations on ingress direction
	// - the maximal connection-set which the policy's rules allow to all namespaces in the cluster on ingress direction
	IngressGeneralConns PolicyGeneralRulesConns
	// EgressGeneralConns contains:
	// - the maximal connection-set which the policy's rules allow to all destinations on egress direction
	// - the maximal connection-set which the policy's rules allow to all namespaces in the cluster on egress direction
	EgressGeneralConns PolicyGeneralRulesConns
}

// @todo might help if while pre-process, to check containment of all rules' connections; if all "specific" rules
// connections are contained in the "general" rules connections, then we can avoid iterating policy rules for computing
// connections between two peers

type PolicyGeneralRulesConns struct {
	// AllDestinationsConns contains the maximal connection-set which the policy's rules allow to all destinations
	// (all namespaces, pods and IP addresses)
	AllDestinationsConns *common.ConnectionSet
	// EntireClusterConns contains the maximal connection-set which the policy's rules allow to all namespaces in the cluster
	EntireClusterConns *common.ConnectionSet
}

// @todo need a network policy collection type along with convenience methods?
// 	if so, also consider concurrent access (or declare not goroutine safe?)

const (
	portBase = 10
	portBits = 32
)

func getProtocolStr(p *v1.Protocol) string {
	if p == nil { // If not specified, this field defaults to TCP.
		return "TCP"
	}
	return string(*p)
}

func (np *NetworkPolicy) convertNamedPort(namedPort string, pod *Pod) int32 {
	return pod.ConvertPodNamedPort(namedPort)
}

// getPortsRange returns the start and end port numbers given input port, endPort and dest peer
// and the portName if it is a named port
// if input port is a named port, and the dst peer is nil or  does not have a matching named port defined, return
// an empty range represented by (-1,-1)
func (np *NetworkPolicy) getPortsRange(port *intstr.IntOrString, endPort *int32, dst Peer) (startNum, endNum int32,
	namedPort string, err error) {
	var start, end int32
	portName := ""
	if port.Type == intstr.String {
		if dst == nil {
			return common.NoPort, common.NoPort, port.StrVal, nil
		}
		if dst.PeerType() != PodType {
			return start, end, "", np.netpolErr(netpolerrors.NamedPortErrTitle, netpolerrors.ConvertNamedPortErrStr)
		}
		portName = port.StrVal
		portNum := np.convertNamedPort(portName, dst.GetPeerPod())
		start = portNum
		end = portNum
	} else {
		start = port.IntVal
		end = start
		if endPort != nil {
			end = *endPort
		}
	}
	return start, end, portName, nil
}

func isEmptyPortRange(start, end int32) bool {
	return start == common.NoPort && end == common.NoPort
}

func (np *NetworkPolicy) ruleConnections(rulePorts []netv1.NetworkPolicyPort, dst Peer) (*common.ConnectionSet, error) {
	if len(rulePorts) == 0 {
		return common.MakeConnectionSet(true), nil // If this field is empty or missing, this rule matches all ports
		// (traffic not restricted by port)
	}
	res := common.MakeConnectionSet(false)
	for i := range rulePorts {
		protocol := v1.ProtocolTCP
		if rulePorts[i].Protocol != nil {
			protocol = *rulePorts[i].Protocol
		}
		ports := common.MakePortSet(false)
		if rulePorts[i].Port == nil {
			ports = common.MakePortSet(true)
		} else {
			startPort, endPort, portName, err := np.getPortsRange(rulePorts[i].Port, rulePorts[i].EndPort, dst)
			if err != nil {
				return res, err
			}
			if (dst == nil || isRepresentativePod(dst)) && portName != "" {
				// adding namedPort to connectionSet in case of :
				// - dst is nil - for general connections;
				// - if dst is a representative pod (its namedPorts are unknown)
				ports.AddPort(intstr.FromString(portName))
			}
			if !isEmptyPortRange(startPort, endPort) {
				ports.AddPortRange(int64(startPort), int64(endPort))
			}
		}
		res.AddConnection(protocol, ports)
	}
	return res, nil
}

// isRepresentativePod determines if the peer's source is representativePeer; i.e. its pod fake and has RepresentativePodName
func isRepresentativePod(peer Peer) bool {
	if peer.GetPeerPod() == nil {
		return false
	}
	return peer.GetPeerPod().IsPodRepresentative()
}

// ruleConnsContain returns true if the given protocol and port are contained in connections allowed by rulePorts
func (np *NetworkPolicy) ruleConnsContain(rulePorts []netv1.NetworkPolicyPort, protocol, port string, dst Peer) (bool, error) {
	if len(rulePorts) == 0 {
		return true, nil // If this field is empty or missing, this rule matches all ports (traffic not restricted by port)
	}
	for i := range rulePorts {
		if strings.ToUpper(protocol) != getProtocolStr(rulePorts[i].Protocol) {
			continue
		}
		if rulePorts[i].Port == nil { // If this field is not provided, this matches all port names and numbers.
			return true, nil
		}
		startPort, endPort, _, err := np.getPortsRange(rulePorts[i].Port, rulePorts[i].EndPort, dst)
		if err != nil {
			return false, err
		}
		if isEmptyPortRange(startPort, endPort) {
			return false, nil
		}
		intPort, err := strconv.ParseInt(port, portBase, portBits)
		if err != nil {
			return false, err
		}
		if intPort >= int64(startPort) && intPort <= int64(endPort) {
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
			return false, np.netpolErr(netpolerrors.RulePeerErrTitle, netpolerrors.EmptyRulePeerErrStr)
		}
		if rulePeers[i].PodSelector != nil || rulePeers[i].NamespaceSelector != nil {
			if rulePeers[i].IPBlock != nil {
				return false, np.netpolErr(netpolerrors.RulePeerErrTitle, netpolerrors.CombinedRulePeerErrStr)
			}
			if peer.PeerType() == IPBlockType {
				continue // assuming that peer of type IP cannot be selected by pod selector
			}
			// peer is a pod
			peerMatchesPodSelector := false
			peerMatchesNamespaceSelector := false
			var err error
			var selector labels.Selector
			if rulePeers[i].NamespaceSelector == nil {
				peerMatchesNamespaceSelector = (np.ObjectMeta.Namespace == peer.GetPeerPod().Namespace)
			} else {
				peerNamespace := peer.GetPeerNamespace()
				// checking if a selector matches labels by peer type; since representative peers selectors may need special handling
				if isRepresentativePod(peer) {
					// representative peer's is inferred from a rule with its labelSelector
					// note that if the namespaceSelector in the rule is nil, we don't get here,
					// since that means the peer is in same namespace of the policy, and this was checked above
					peerMatchesNamespaceSelector, err = SelectorsFullMatch(rulePeers[i].NamespaceSelector, peer.GetPeerPod().RepresentativeNsLabelSelector)
				} else {
					selector, err = np.parseNetpolLabelSelector(rulePeers[i].NamespaceSelector)
					peerMatchesNamespaceSelector = selector.Matches(labels.Set(peerNamespace.Labels))
				}
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
				// checking if a selector matches labels by peer type; since representative peers selectors may need special handling
				if isRepresentativePod(peer) {
					peerMatchesPodSelector, err = SelectorsFullMatch(rulePeers[i].PodSelector, peer.GetPeerPod().RepresentativePodLabelSelector)
				} else {
					selector, err = np.parseNetpolLabelSelector(rulePeers[i].PodSelector)
					peerMatchesPodSelector = selector.Matches(labels.Set(peer.GetPeerPod().Labels))
				}
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

			peerIPBlock := peer.GetPeerIPBlock()
			res := peerIPBlock.ContainedIn(ruleIPBlock)
			if res {
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

		peerSselected, err := np.ruleSelectsPeer(rulePeers, src)
		if err != nil {
			return false, err
		}
		if !peerSselected {
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

		peerSselected, err := np.ruleSelectsPeer(rulePeers, dst)
		if err != nil {
			return false, err
		}
		if !peerSselected {
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

// GetEgressAllowedConns returns the set of allowed connections from any captured pod to the destination peer
func (np *NetworkPolicy) GetEgressAllowedConns(dst Peer) (*common.ConnectionSet, error) {
	res := common.MakeConnectionSet(false)
	for _, rule := range np.Spec.Egress {
		rulePeers := rule.To
		rulePorts := rule.Ports
		peerSselected, err := np.ruleSelectsPeer(rulePeers, dst)
		if err != nil {
			return res, err
		}
		if !peerSselected {
			continue
		}
		ruleConns, err := np.ruleConnections(rulePorts, dst)
		if err != nil {
			return res, err
		}
		res.Union(ruleConns)
		if res.AllowAll {
			return res, nil
		}
	}
	return res, nil
}

// GetIngressAllowedConns returns the set of allowed connections to a captured dst pod from the src peer
func (np *NetworkPolicy) GetIngressAllowedConns(src, dst Peer) (*common.ConnectionSet, error) {
	res := common.MakeConnectionSet(false)
	for _, rule := range np.Spec.Ingress {
		rulePeers := rule.From
		rulePorts := rule.Ports
		peerSselected, err := np.ruleSelectsPeer(rulePeers, src)
		if err != nil {
			return res, err
		}
		if !peerSselected {
			continue
		}

		ruleConns, err := np.ruleConnections(rulePorts, dst)
		if err != nil {
			return res, err
		}
		res.Union(ruleConns)
		if res.AllowAll {
			return res, nil
		}
	}
	return res, nil
}

func (np *NetworkPolicy) netpolErr(title, description string) error {
	return fmt.Errorf("network policy %s %s: %s", np.fullName(), title, description)
}

func (np *NetworkPolicy) parseNetpolCIDR(cidr string, except []string) (*ipblock.IPBlock, error) {
	ipb, err := ipblock.FromCidr(cidr)
	if err != nil {
		return nil, np.netpolErr(netpolerrors.CidrErrTitle, err.Error())
	}
	ipb, err = ipb.ExceptCidrs(except...)
	if err != nil {
		return nil, np.netpolErr(netpolerrors.CidrErrTitle, err.Error())
	}
	return ipb, nil
}

func (np *NetworkPolicy) parseNetpolLabelSelector(selector *metav1.LabelSelector) (labels.Selector, error) {
	selectorRes, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return nil, np.netpolErr(netpolerrors.SelectorErrTitle, err.Error())
	}
	return selectorRes, nil
}

func (np *NetworkPolicy) rulePeersReferencedIPBlocks(rulePeers []netv1.NetworkPolicyPeer) ([]*ipblock.IPBlock, error) {
	res := []*ipblock.IPBlock{}
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

// GetReferencedIPBlocks: return list of IPBlock objects referenced in the current network policy
func (np *NetworkPolicy) GetReferencedIPBlocks() ([]*ipblock.IPBlock, error) {
	res := []*ipblock.IPBlock{}
	for _, rule := range np.Spec.Ingress {
		ruleRes, err := np.rulePeersReferencedIPBlocks(rule.From)
		if err != nil {
			return nil, err
		}
		res = append(res, ruleRes...)
	}
	for _, rule := range np.Spec.Egress {
		ruleRes, err := np.rulePeersReferencedIPBlocks(rule.To)
		if err != nil {
			return nil, err
		}
		res = append(res, ruleRes...)
	}
	return res, nil
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

func (np *NetworkPolicy) fullName() string {
	return types.NamespacedName{Name: np.Name, Namespace: np.Namespace}.String()
}

// /////////////////////////////////////////////////////////////////////////////////////////////
// pre-processing computations - currently performed for exposure-analysis goals only;

// SingleRuleSelectors contains LabelSelector objects representing namespaceSelector or/and podSelector
// of a single rule in the policy
type SingleRuleSelectors struct {
	NsSelector  *metav1.LabelSelector
	PodSelector *metav1.LabelSelector
	// policyNsFlag indicates if the rule contains only podSelector;
	// so the representative peer will be created in the policy's namespace
	PolicyNsFlag bool
}

// DefaultNamespaceLabelsMap returns a map with a single key: val for the default K8s namespace name key.
// to be used in case the labels representing a namespace should contain this matchLabel only.
func DefaultNamespaceLabelsMap(namespaceName string) map[string]string {
	return map[string]string{common.K8sNsNameLabelKey: namespaceName}
}

// ScanPolicyRulesForGeneralConnsAndRepresentativePeers scans policy rules and :
// - updates policy's general connections with all destinations or/ and with entire cluster for ingress and/ or egress directions
// - returns list of labels.selectors from rules which has non-empty selectors
func (np *NetworkPolicy) ScanPolicyRulesForGeneralConnsAndRepresentativePeers() (rulesSelectors []SingleRuleSelectors, err error) {
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

// scanIngressRules handles policy's ingress rules (for updating policy's general conns/ returning specific rules' selectors)
func (np *NetworkPolicy) scanIngressRules() ([]SingleRuleSelectors, error) {
	rulesSelectors := []SingleRuleSelectors{}
	for _, rule := range np.Spec.Ingress {
		rulePeers := rule.From
		rulePorts := rule.Ports
		selectors, err := np.handleRulesSelectors(rulePeers, rulePorts, true)
		if err != nil {
			return nil, err
		}
		rulesSelectors = append(rulesSelectors, selectors...)
	}
	return rulesSelectors, nil
}

// scanEgressRules handles policy's egress rules (for updating policy's general conns/ returning specific rules' selectors)
func (np *NetworkPolicy) scanEgressRules() ([]SingleRuleSelectors, error) {
	rulesSelectors := []SingleRuleSelectors{}
	for _, rule := range np.Spec.Egress {
		rulePeers := rule.To
		rulePorts := rule.Ports
		selectors, err := np.handleRulesSelectors(rulePeers, rulePorts, false)
		if err != nil {
			return nil, err
		}
		// rule with selectors selecting specific namespaces/ pods
		rulesSelectors = append(rulesSelectors, selectors...)
	}
	return rulesSelectors, nil
}

// handleRulesSelectors :
// - checks if the given rules list is exposed to entire world or entire cluster
// (e.g. if the rules list is empty/ if there is a rule with: empty namespaceSelector/ both empty nameSpaceSelector and podSelector) :
// then updates the policy's general conns
// - else: returns selectors of non-general rules (rules that are not exposed to entire world or cluster).
// this func assumes rules are legal (rules correctness check occurs later)
func (np *NetworkPolicy) handleRulesSelectors(rules []netv1.NetworkPolicyPeer, rulePorts []netv1.NetworkPolicyPort,
	isIngress bool) (rulesSelectors []SingleRuleSelectors, err error) {
	if len(rules) == 0 {
		err = np.updateNetworkPolicyGeneralConn(true, true, rulePorts, isIngress)
		return nil, err
	}
	for i := range rules {
		var ruleSel SingleRuleSelectors
		if rules[i].IPBlock != nil {
			continue
		}
		// a rule is exposed to entire cluster if :
		// 1. the podSelector is nil (no podselector) but the namespaceSelector is empty ({}) not nil
		// 2. both podSelector and namespaceSelector are empty ({})
		if rules[i].NamespaceSelector != nil && rules[i].NamespaceSelector.Size() == 0 &&
			(rules[i].PodSelector == nil || rules[i].PodSelector.Size() == 0) {
			err = np.updateNetworkPolicyGeneralConn(false, true, rulePorts, isIngress)
			return nil, err
		}
		// else selectors' combination specifies end-points (at least one is not nil)
		ruleSel.PodSelector = rules[i].PodSelector
		ruleSel.NsSelector = rules[i].NamespaceSelector
		if rules[i].NamespaceSelector == nil {
			// special case: ns selector is nil but podSelector is not, so the namespace of the rule is
			// the policy's namespace; (turn on the indicator)
			ruleSel.PolicyNsFlag = true
			ruleSel.NsSelector = &metav1.LabelSelector{MatchLabels: DefaultNamespaceLabelsMap(np.Namespace)}
		}
		rulesSelectors = append(rulesSelectors, ruleSel)
	}
	return rulesSelectors, nil
}

// updateNetworkPolicyGeneralConn updates the general connections of the policy
func (np *NetworkPolicy) updateNetworkPolicyGeneralConn(allDests, entireCluster bool, rulePorts []netv1.NetworkPolicyPort,
	isIngress bool) error {
	ruleConns, err := np.ruleConnections(rulePorts, nil)
	if err != nil {
		return err
	}
	if allDests {
		if isIngress {
			np.IngressGeneralConns.AllDestinationsConns.Union(ruleConns)
		} else {
			np.EgressGeneralConns.AllDestinationsConns.Union(ruleConns)
		}
	}
	if entireCluster {
		if isIngress {
			np.IngressGeneralConns.EntireClusterConns.Union(ruleConns)
		} else {
			np.EgressGeneralConns.EntireClusterConns.Union(ruleConns)
		}
	}
	return nil
}
