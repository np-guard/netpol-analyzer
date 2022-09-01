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
	"errors"
	"net"
	"strconv"
	"strings"

	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const portBase = 10
const portBits = 32

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

func getProtocolStr(p *v1.Protocol) string {
	if p == nil { // If not specified, this field defaults to TCP.
		return "TCP"
	}
	return string(*p)
}

func convertNamedPort(namedPort string, pod *Pod) (int32, error) {
	for _, containerPort := range pod.Ports {
		if namedPort == containerPort.Name {
			return containerPort.ContainerPort, nil
		}
	}
	return 0, errors.New("no matching named port")
}

func getPortsRange(port *intstr.IntOrString, endPort *int32, dst Peer) (int32, int32, error) {
	var start, end int32
	if port.Type == intstr.String {
		if dst.PeerType != PodType || dst.Pod == nil {
			return start, end, errors.New("cannot convert named port on extenral ip destination")
		}
		portNum, err := convertNamedPort(port.StrVal, dst.Pod)
		if err != nil {
			return start, end, err
		}
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

func ruleConnections(rulePorts []netv1.NetworkPolicyPort, dst Peer) ConnectionSet {
	if len(rulePorts) == 0 {
		return MakeConnectionSet(true) // If this field is empty or missing, this rule matches all ports (traffic not restricted by port)
	}
	res := MakeConnectionSet(false)
	for i := range rulePorts {
		protocol := v1.ProtocolTCP
		if rulePorts[i].Protocol != nil {
			protocol = *rulePorts[i].Protocol
		}
		ports := PortSet{}
		if rulePorts[i].Port == nil {
			ports = MakePortSet(true)
		} else {
			startPort, endPort, err := getPortsRange(rulePorts[i].Port, rulePorts[i].EndPort, dst)
			if err == nil {
				ports.AddPortRange(int64(startPort), int64(endPort))
			}
		}
		res.AddConnection(protocol, ports)
	}
	return res
}

// ruleConnsContain returns true if the given protocol and port are contained in connections allowed by rulePorts
func ruleConnsContain(rulePorts []netv1.NetworkPolicyPort, protocol, port string, dst Peer) (bool, error) {
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
		startPort, endPort, err := getPortsRange(rulePorts[i].Port, rulePorts[i].EndPort, dst)
		if err != nil {
			return false, err
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
		if rulePeers[i].PodSelector != nil || rulePeers[i].NamespaceSelector != nil {
			if rulePeers[i].IPBlock != nil {
				return false, errors.New("rulePeers of type NetworkPolicyPeer -cannot have both IPBlock and PodSelector/NamespaceSelector set")
			}
			if peer.PeerType == Iptype {
				continue // assuming that peer of type IP cannot be selected by pod selector
			}
			// peer is a pod
			peerMatchesPodSelector := false
			peerMatchesNamespaceSelector := false
			if rulePeers[i].NamespaceSelector == nil {
				peerMatchesNamespaceSelector = (np.ObjectMeta.Namespace == peer.Pod.Namespace)
			} else {
				selector, err := metav1.LabelSelectorAsSelector(rulePeers[i].NamespaceSelector)
				if err != nil {
					return false, err
				}
				peerNamespace := peer.Namespace
				peerMatchesNamespaceSelector = selector.Matches(labels.Set(peerNamespace.Labels))
			}
			if !peerMatchesNamespaceSelector {
				continue // skip to next peerObj
			}
			if rulePeers[i].PodSelector == nil {
				peerMatchesPodSelector = true
			} else {
				selector, err := metav1.LabelSelectorAsSelector(rulePeers[i].PodSelector)
				if err != nil {
					return false, err
				}
				peerMatchesPodSelector = selector.Matches(labels.Set(peer.Pod.Labels))
			}
			if peerMatchesPodSelector {
				return true, nil //  matching both pod selector and ns_selector here
			}
		} else if rulePeers[i].IPBlock != nil {
			if peer.PeerType == PodType {
				continue // assuming that peer of type Pod cannot be selected by IPBlock
				// TODO: is this reasonable to assume?
			}
			// check that peer.IP matches the IPBlock
			cidr := rulePeers[i].IPBlock.CIDR
			_, ipnetA, _ := net.ParseCIDR(cidr)
			ipB := net.ParseIP(peer.IP)
			res1 := ipnetA.Contains(ipB)
			if !res1 {
				continue
			}
			res2 := false
			for _, excepctCidr := range rulePeers[i].IPBlock.Except {
				_, ipnetC, _ := net.ParseCIDR(excepctCidr)
				res2 = res2 || ipnetC.Contains(ipB)
				if res2 {
					break
				}
			}
			if !res2 {
				return true, nil
			}
		} else {
			// unexpected obj -> at podselector / ipblock should be set?
			return false, errors.New("rulePeers of type NetworkPolicyPeer - all fields are empty")
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
		connSelected, err := ruleConnsContain(rulePorts, protocol, port, dst)
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
		connSelected, err := ruleConnsContain(rulePorts, protocol, port, dst)
		if err != nil {
			return false, err
		}
		if connSelected {
			return true, nil
		}
	}
	return false, nil
}

func (np *NetworkPolicy) GetEgressAllowedConns(dst Peer) ConnectionSet {
	res := MakeConnectionSet(false)
	for _, rule := range np.Spec.Egress {
		rulePeers := rule.To
		rulePorts := rule.Ports
		peerSselected, err := np.ruleSelectsPeer(rulePeers, dst)
		if err != nil || !peerSselected {
			continue
		}
		ruleConns := ruleConnections(rulePorts, dst)
		res.Union(ruleConns)
		if res.AllowAll {
			return res
		}
	}
	return res
}

func (np *NetworkPolicy) GetIngressAllowedConns(src, dst Peer) ConnectionSet {
	res := MakeConnectionSet(false)
	for _, rule := range np.Spec.Ingress {
		rulePeers := rule.From
		rulePorts := rule.Ports
		peerSselected, err := np.ruleSelectsPeer(rulePeers, src)
		if err != nil || !peerSselected {
			continue
		}
		ruleConns := ruleConnections(rulePorts, dst)
		res.Union(ruleConns)
		if res.AllowAll {
			return res
		}
	}
	return res
}

func rulePeersReferencedIPBlocks(rulePeers []netv1.NetworkPolicyPeer) []*IPBlock {
	res := []*IPBlock{}
	for _, peerObj := range rulePeers {
		if peerObj.IPBlock != nil {
			ipb, err := NewIPBlock(peerObj.IPBlock.CIDR, peerObj.IPBlock.Except)
			if err == nil {
				res = append(res, ipb.split()...)
			}
		}
	}
	return res
}

func (np *NetworkPolicy) GetReferencedIPBlocks() []*IPBlock {
	res := []*IPBlock{}
	for _, rule := range np.Spec.Ingress {
		res = append(res, rulePeersReferencedIPBlocks(rule.From)...)
	}
	for _, rule := range np.Spec.Egress {
		res = append(res, rulePeersReferencedIPBlocks(rule.To)...)
	}
	return res
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

	selector, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
	if err != nil {
		return false, err
	}
	return selector.Matches(labels.Set(p.Labels)), nil
}
