// Copyright 2022
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
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

	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// NetworkPolicy is an alias for k8s network policy object
// @todo is there a preprocessed form of the object that would make more sense?
//
//	for example, converting Spec.PodSelector to labels.Selector on initialization
//	or preprocessing namespaces and pods that match selector in ingress/egress rules, etc
//
// -> might help to preprocess and store peers that match policy selectors + selectors in rules + set of allowed connections per rule
type NetworkPolicy netv1.NetworkPolicy

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
// if input port is a named port, and the dst peer does not have a matching named port defined, return
// an empty range represented by (-1,-1)
func (np *NetworkPolicy) getPortsRange(port *intstr.IntOrString, endPort *int32, dst Peer) (startNum, endNum int32, err error) {
	var start, end int32
	if port.Type == intstr.String {
		if dst.PeerType() != PodType {
			return start, end, np.netpolErr(netpolerrors.NamedPortErrTitle, netpolerrors.ConvertNamedPortErrStr)
		}
		portNum := np.convertNamedPort(port.StrVal, dst.GetPeerPod())
		start = portNum
		end = portNum
	} else {
		start = port.IntVal
		end = start
		if endPort != nil {
			end = *endPort
		}
	}
	return start, end, nil
}

func isEmptyPortRange(start, end int32) bool {
	return start == noPort && end == noPort
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
		ports := common.PortSet{}
		if rulePorts[i].Port == nil {
			ports = common.MakePortSet(true)
		} else {
			startPort, endPort, err := np.getPortsRange(rulePorts[i].Port, rulePorts[i].EndPort, dst)
			if err != nil {
				return res, err
			}
			if isEmptyPortRange(startPort, endPort) {
				continue
			}

			ports.AddPortRange(int64(startPort), int64(endPort))
		}
		res.AddConnection(protocol, ports)
	}
	return res, nil
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
		startPort, endPort, err := np.getPortsRange(rulePorts[i].Port, rulePorts[i].EndPort, dst)
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
			if rulePeers[i].NamespaceSelector == nil {
				peerMatchesNamespaceSelector = (np.ObjectMeta.Namespace == peer.GetPeerPod().Namespace)
			} else {
				selector, err := np.parseNetpolLabelSelector(rulePeers[i].NamespaceSelector)
				if err != nil {
					return false, err
				}
				peerNamespace := peer.GetPeerNamespace()
				peerMatchesNamespaceSelector = selector.Matches(labels.Set(peerNamespace.Labels))
			}
			if !peerMatchesNamespaceSelector {
				continue // skip to next peerObj
			}
			if rulePeers[i].PodSelector == nil {
				peerMatchesPodSelector = true
			} else {
				selector, err := np.parseNetpolLabelSelector(rulePeers[i].PodSelector)
				if err != nil {
					return false, err
				}
				peerMatchesPodSelector = selector.Matches(labels.Set(peer.GetPeerPod().Labels))
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

// GetIngressAllowedConns returns true  if the given connections from src to any of the pods captured by the policy is allowed
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

// GetEgressAllowedConns returns true if the given connection to dst from any of the pods captured by the policy is allowed
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

// GetEgressAllowedConns returns the set of allowed connetions from any captured pod to the destination peer
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

func (np *NetworkPolicy) parseNetpolCIDR(cidr string, except []string) (*common.IPBlock, error) {
	ipb, err := common.NewIPBlock(cidr, except)
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

func (np *NetworkPolicy) rulePeersReferencedIPBlocks(rulePeers []netv1.NetworkPolicyPeer) ([]*common.IPBlock, error) {
	res := []*common.IPBlock{}
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
func (np *NetworkPolicy) GetReferencedIPBlocks() ([]*common.IPBlock, error) {
	res := []*common.IPBlock{}
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
