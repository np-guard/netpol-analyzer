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

	"github.com/np-guard/models/pkg/netset"

	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
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
	// IngressPolicyExposure contains:
	// - the maximal connection-set which the policy's rules allow from external destinations on ingress direction
	// - the maximal connection-set which the policy's rules allow from all namespaces in the cluster on ingress direction
	IngressPolicyExposure PolicyExposureWithoutSelectors
	// EgressPolicyExposure contains:
	// - the maximal connection-set which the policy's rules allow to external destinations on egress direction
	// - the maximal connection-set which the policy's rules allow to all namespaces in the cluster on egress direction
	EgressPolicyExposure PolicyExposureWithoutSelectors
}

// @todo might help if while pre-process, to check containment of all rules' connections; if all "specific" rules
// connections are contained in the "general" rules connections, then we can avoid iterating policy rules for computing
// connections between two peers

// PolicyExposureWithoutSelectors describes the maximum allowed conns that the policy exposes as cluster wide or as external,
// those conns are inferred when the policy has no rules, or from empty rules
type PolicyExposureWithoutSelectors struct {
	// ExternalExposure  contains the maximal connection-set which the policy's rules allow from/to external and cluster-wide destinations
	// (all namespaces, pods and IP addresses)
	ExternalExposure *common.ConnectionSet
	// ClusterWideExposure  contains the maximal connection-set which the policy's rules allow from/to all namespaces in the cluster
	ClusterWideExposure *common.ConnectionSet
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

// getPortsRange given a rule port and dest peer, returns: the start and end port numbers,
// or the port name if it is a named port
// if input port is a named port, and the dst peer is nil or does not have a matching named port defined, returns
// an empty range represented by (-1,-1) with the named port string
func (np *NetworkPolicy) getPortsRange(rulePort netv1.NetworkPolicyPort, dst Peer) (start, end int32,
	portName string, err error) {
	if rulePort.Port.Type == intstr.String { // rule.Port is namedPort
		ruleProtocol := getProtocolStr(rulePort.Protocol)
		portName = rulePort.Port.StrVal
		if dst == nil {
			// dst is nil, so the namedPort can not be converted, return string port name
			return common.NoPort, common.NoPort, portName, nil
		}
		if dst.PeerType() != PodType {
			// namedPort is not defined for IP-blocks
			return start, end, "", np.netpolErr(netpolerrors.NamedPortErrTitle, netpolerrors.ConvertNamedPortErrStr)
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
		start = podPortNum
		end = podPortNum
	} else { // rule.Port is number
		start = rulePort.Port.IntVal
		end = start
		if rulePort.EndPort != nil {
			end = *rulePort.EndPort
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
			startPort, endPort, portName, err := np.getPortsRange(rulePorts[i], dst)
			if err != nil {
				return res, err
			}
			// valid returned values from `getsPortsRange` :
			// 1. empty-numbered-range with the string namedPort, if the rule has a named-port which is not (or cannot be) converted to a
			// numbered-range by the dst's ports.
			//  2. non empty-range when the rule ports are numbered or the named-port was converted
			if (dst == nil || isPeerRepresentative(dst)) && isEmptyPortRange(startPort, endPort) && portName != "" {
				// this func may be called:
				// 1- for computing cluster-wide exposure of the policy (dst is nil);
				// 2- in-order to get a connection from a real workload to a representative dst.
				// in both first cases, we can't convert the named port to its number, like when dst peer is a real
				// pod from manifests, so we use the named-port as is.
				// 3- in order to get a connection from any pod to a real dst.
				// in the third case the namedPort of the policy rule may not have a match in the Pod's configuration,
				// so it will be ignored (the pod has no matching named-port in its configuration - unknown connection is not allowed)
				// 4- in order to get a connection from any pod to an ip dst (will not get here, as named ports are not defined for ip-blocks)

				// adding portName string to the portSet
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

// isPeerRepresentative  determines if the peer's source is representativePeer; i.e. its pod fake and has RepresentativePodName
func isPeerRepresentative(peer Peer) bool {
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
		startPort, endPort, _, err := np.getPortsRange(rulePorts[i], dst)
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
			if rulePeers[i].NamespaceSelector == nil {
				peerMatchesNamespaceSelector = (np.ObjectMeta.Namespace == peer.GetPeerPod().Namespace)
			} else {
				peerNamespace := peer.GetPeerNamespace()
				var peerNsLabels map[string]string
				if peerNamespace != nil { // peerNamespace may be nil for representative peers
					peerNsLabels = peerNamespace.Labels
				}
				peerMatchesNamespaceSelector, err = np.selectorsMatch(rulePeers[i].NamespaceSelector, peer.GetPeerPod().RepresentativeNsLabelSelector,
					peerNsLabels, isPeerRepresentative(peer))
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
				peerMatchesPodSelector, err = np.selectorsMatch(rulePeers[i].PodSelector, peer.GetPeerPod().RepresentativePodLabelSelector,
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

			peerIPBlock := peer.GetPeerIPBlock()
			res := peerIPBlock.IsSubset(ruleIPBlock)
			if res {
				return true, nil
			}
		}
	}
	return false, nil
}

// selectorsMatch checks if the given selectors match each other.
// called either with namespace-selectors, or with pod-selectors
// when exposure analysis is on : checks the match between rule selector and the relevant representativePeer selector
// otherwise, checks match between rule-selector and pod/namespace labels
func (np *NetworkPolicy) selectorsMatch(ruleSelector, peerSelector *metav1.LabelSelector, peerLabels map[string]string,
	isPeerRepresentative bool) (selectorsMatch bool, err error) {
	// for exposure analysis (representative-peer), use relevant func to check if representative peer is matched by rule's selector
	if isPeerRepresentative {
		// representative peer is inferred from a rule:
		// - by having representative selector pointing to same reference of the rule's selector
		// - or by having representative labelSelector with requirements equal to the rule's requirements
		// note that if the given ruleSelector is nil, we don't get here.
		return SelectorsFullMatch(ruleSelector, peerSelector)
	} // else for real peer just check if the selector matches the peer's labels
	selector, err := np.parseNetpolLabelSelector(ruleSelector)
	if err != nil {
		return false, err
	}
	return selector.Matches(labels.Set(peerLabels)), nil
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

// GetEgressAllowedConns returns the set of allowed connections from any captured pod to the destination peer
func (np *NetworkPolicy) GetEgressAllowedConns(dst Peer) (*common.ConnectionSet, error) {
	res := common.MakeConnectionSet(false)
	for _, rule := range np.Spec.Egress {
		rulePeers := rule.To
		rulePorts := rule.Ports
		peerSelected, err := np.ruleSelectsPeer(rulePeers, dst)
		if err != nil {
			return res, err
		}
		if !peerSelected {
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
		peerSelected, err := np.ruleSelectsPeer(rulePeers, src)
		if err != nil {
			return res, err
		}
		if !peerSelected {
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

func (np *NetworkPolicy) parseNetpolCIDR(cidr string, except []string) (*netset.IPBlock, error) {
	ipb, err := netset.IPBlockFromCidr(cidr)
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

// GetReferencedIPBlocks: return list of IPBlock objects referenced in the current network policy
func (np *NetworkPolicy) GetReferencedIPBlocks() ([]*netset.IPBlock, error) {
	res := []*netset.IPBlock{}
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
}

// GetPolicyRulesSelectorsAndUpdateExposureClusterWideConns scans policy rules and :
// - updates policy's exposed cluster-wide connections from/to external resources or/and from/to all namespaces in the cluster on
// ingress and egress directions
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
	for _, rule := range np.Spec.Ingress {
		rulePeers := rule.From
		rulePorts := rule.Ports
		selectors, err := np.getSelectorsAndUpdateExposureClusterWideConns(rulePeers, rulePorts, true)
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
	for _, rule := range np.Spec.Egress {
		rulePeers := rule.To
		rulePorts := rule.Ports
		selectors, err := np.getSelectorsAndUpdateExposureClusterWideConns(rulePeers, rulePorts, false)
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
// - if the rules list is empty updates the external and cluster wide exposure of the policy
// - if a rule have empty selectors (podSelector and namespaceSelector)or just empty namespaceSelector (nil podSelector)
// updates the cluster wide exposure of the policy
// - if a rule contains at least one defined selector : appends the rule selectors to a selector list which will be returned.
// this func assumes rules are legal (rules correctness check occurs later)
func (np *NetworkPolicy) getSelectorsAndUpdateExposureClusterWideConns(rules []netv1.NetworkPolicyPeer, rulePorts []netv1.NetworkPolicyPort,
	isIngress bool) (rulesSelectors []SingleRuleSelectors, err error) {
	if len(rules) == 0 {
		err = np.updateNetworkPolicyExposureClusterWideConns(true, true, rulePorts, isIngress)
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
		if rules[i].NamespaceSelector != nil && rules[i].NamespaceSelector.Size() == 0 &&
			(rules[i].PodSelector == nil || rules[i].PodSelector.Size() == 0) {
			err = np.updateNetworkPolicyExposureClusterWideConns(false, true, rulePorts, isIngress)
			return nil, err
		}
		// else selectors' combination specifies workloads by labels (at least one is not nil and not empty)
		ruleSel.PodSelector = rules[i].PodSelector
		ruleSel.NsSelector = rules[i].NamespaceSelector
		rulesSelectors = append(rulesSelectors, ruleSel)
	}
	return rulesSelectors, nil
}

// updateNetworkPolicyExposureClusterWideConns updates the cluster-wide exposure connections of the policy
func (np *NetworkPolicy) updateNetworkPolicyExposureClusterWideConns(externalExposure, entireCluster bool,
	rulePorts []netv1.NetworkPolicyPort, isIngress bool) error {
	ruleConns, err := np.ruleConnections(rulePorts, nil)
	if err != nil {
		return err
	}
	if externalExposure {
		if isIngress {
			np.IngressPolicyExposure.ExternalExposure.Union(ruleConns)
		} else {
			np.EgressPolicyExposure.ExternalExposure.Union(ruleConns)
		}
	}
	if entireCluster {
		if isIngress {
			np.IngressPolicyExposure.ClusterWideExposure.Union(ruleConns)
		} else {
			np.EgressPolicyExposure.ClusterWideExposure.Union(ruleConns)
		}
	}
	return nil
}
