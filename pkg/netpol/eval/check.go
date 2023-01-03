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
package eval

import (
	"errors"
	"fmt"
	"net"
	"strings"

	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval/internal/k8s"
)

// CheckIfAllowed returns true if the given input connection is allowed by network policies
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

// AllAllowedConnectionsBetweenPeers: returns the allowed connections from srcPeer to dstPeer
func (pe *PolicyEngine) AllAllowedConnectionsBetweenPeers(srcPeer, dstPeer Peer) (Connection, error) {
	srcK8sPeer := srcPeer.(k8s.Peer)
	dstK8sPeer := dstPeer.(k8s.Peer)
	res := k8s.ConnectionSet{}
	// cases where any connection is always allowed
	if isPodToItself(srcK8sPeer, dstK8sPeer) || isPeerNodeIP(srcK8sPeer, dstK8sPeer) || isPeerNodeIP(dstK8sPeer, srcK8sPeer) {
		conn := k8s.MakeConnectionSet(true)
		return getConnectionObject(conn), nil
	}
	// egress
	res = pe.allallowedXgressConnections(srcK8sPeer, dstK8sPeer, false)
	if res.IsEmpty() {
		return getConnectionObject(res), nil
	}
	// ingress
	res.Intersection(pe.allallowedXgressConnections(srcK8sPeer, dstK8sPeer, true))
	return getConnectionObject(res), nil
}

// getPod: returns a Pod object corresponding to the input pod name
func (pe *PolicyEngine) getPod(p string) *k8s.Pod {
	if pod, ok := pe.podsMap[p]; ok {
		return pod
	}
	return nil
}

// TODO: consider caching: for each pod and direction, test set of policies that are selecting it
// getPoliciesSelectingPod returns a list of policies that select the input pod on the required direction (ingress/egress)
func (pe *PolicyEngine) getPoliciesSelectingPod(p *k8s.Pod, direction netv1.PolicyType) []*k8s.NetworkPolicy {
	netpols := pe.netpolsMap[p.Namespace]
	res := []*k8s.NetworkPolicy{}
	for _, policy := range netpols {
		selects, err := policy.Selects(p, direction)
		if err == nil && selects {
			res = append(res, policy)
		}
	}
	return res
}

// allowedXgressConnections returns true if the given connection from src to dst on given direction(ingress/egress)
// is allowed by network policies rules
func (pe *PolicyEngine) allowedXgressConnection(src, dst k8s.Peer, isIngress bool, protocol, port string) (bool, error) {
	// relevant policies: policies that capture dst if isIngress, else policies that capture src
	var netpols []*k8s.NetworkPolicy
	if isIngress {
		if dst.PeerType() == k8s.IPBlockType {
			return true, nil // all connections allowed - no restrictions on ingress to externalIP
		}
		netpols = pe.getPoliciesSelectingPod(dst.(*k8s.PodPeer).Pod, netv1.PolicyTypeIngress)
	} else {
		if src.PeerType() == k8s.IPBlockType {
			return true, nil // all connections allowed - no restrictions on egress from externalIP
		}
		netpols = pe.getPoliciesSelectingPod(src.(*k8s.PodPeer).Pod, netv1.PolicyTypeEgress)
	}

	if len(netpols) == 0 { // no networkpolicy captures the relevant pod on the required direction
		return true, nil // all connections allowed
	}

	// iterate relevant network policies (that capture the required pod)
	for _, policy := range netpols {
		// if isIngress: check for ingress rules that capture src within 'from'
		// if not isIngress: check for egress rulres that capture dst within 'to'
		if isIngress {
			res, err := policy.IngressAllowedConn(src, protocol, port, dst)
			if err != nil {
				return false, err
			}
			if res {
				return true, nil
			}
		} else {
			res, err := policy.EgressAllowedConn(dst, protocol, port)
			if err != nil {
				return false, err
			}
			if res {
				return true, nil
			}
		}
	}
	return false, nil
}

// allallowedXgressConnections returns the set of allowed connections from src to dst on given
// direction(ingress/egress), by network policies rules
func (pe *PolicyEngine) allallowedXgressConnections(src, dst k8s.Peer, isIngress bool) k8s.ConnectionSet {
	// relevant policies: policies that capture dst if isIngress, else policies that capture src
	var netpols []*k8s.NetworkPolicy
	if isIngress {
		if dst.PeerType() == k8s.IPBlockType {
			return k8s.MakeConnectionSet(true) // all connections allowed - no restrictions on ingress to externalIP
		}
		netpols = pe.getPoliciesSelectingPod(dst.GetPeerPod(), netv1.PolicyTypeIngress)
	} else {
		if src.PeerType() == k8s.IPBlockType {
			return k8s.MakeConnectionSet(true) // all connections allowed - no restrictions on egress from externalIP
		}
		netpols = pe.getPoliciesSelectingPod(src.GetPeerPod(), netv1.PolicyTypeEgress)
	}

	if len(netpols) == 0 {
		return k8s.MakeConnectionSet(true) // all connections allowed - no networkpolicy captures the relevant pod on the required direction
	}

	allowedConns := k8s.MakeConnectionSet(false)

	// iterate relevant network policies (that captuer the required pod)
	for _, policy := range netpols {
		// if isIngress: check for ingress rules that capture src within 'from'
		// if not isIngress: check for egress rulres that capture dst within 'to'
		// collect the allowed connectivity from the relevant rules into allowedConns
		if isIngress {
			allowedConns.Union(policy.GetIngressAllowedConns(src, dst))
		} else {
			allowedConns.Union(policy.GetEgressAllowedConns(dst))
		}
	}

	return allowedConns
}

// isPeerNodeIP returns true if peer1 is an IP address of a node and peer2 is a pod on that node
func isPeerNodeIP(peer1, peer2 k8s.Peer) bool {
	return peer2.PeerType() == k8s.PodType && peer1.PeerType() == k8s.IPBlockType &&
		peer1.GetPeerIPBlock().IsIPAddress(peer2.GetPeerPod().HostIP)
}

func isPodToItself(peer1, peer2 k8s.Peer) bool {
	return peer1.PeerType() == k8s.PodType && peer2.PeerType() == k8s.PodType &&
		peer1.GetPeerPod().Name == peer2.GetPeerPod().Name && peer1.GetPeerPod().Namespace == peer2.GetPeerPod().Namespace
}

func (pe *PolicyEngine) getPeer(p string) (k8s.Peer, error) {
	// check if input peer is cidr
	if _, _, err := net.ParseCIDR(p); err == nil {
		peerIPBlock, err := k8s.NewIPBlock(p, []string{})
		if err != nil {
			return nil, err
		}
		return &k8s.IPBlockPeer{IPBlock: peerIPBlock}, nil
	}
	// check if input peer is an ip address
	if net.ParseIP(p) != nil {
		peerIPBlock, err := k8s.NewIPBlockFromIPAddress(p)
		if err != nil {
			return nil, err
		}
		return &k8s.IPBlockPeer{IPBlock: peerIPBlock}, nil
	}
	// check if input peer is a pod name
	if strings.Contains(p, string(types.Separator)) { // pod name
		podObj := pe.getPod(p)
		if podObj != nil {
			res := &k8s.PodPeer{Pod: podObj}
			namespaceStr := podObj.Namespace
			if namespaceStr == metav1.NamespaceNone {
				namespaceStr = metav1.NamespaceDefault
			}
			nsObj, ok := pe.namspacesMap[namespaceStr]
			if !ok {
				return nil, errors.New("could not find peer namespace")
			}
			res.NamespaceObject = nsObj
			return res, nil
		}
		return nil, fmt.Errorf("could not find peer %s", p)
	}
	return nil, fmt.Errorf("%s is not a valid peer", p)
}

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

// allAllowedConnections: returns allowed connection between input strings of src and dst
// currently used only for testing
func (pe *PolicyEngine) allAllowedConnections(src, dst string) (k8s.ConnectionSet, error) {
	res := k8s.ConnectionSet{}
	srcPeer, err := pe.getPeer(src)
	if err != nil {
		return res, err
	}
	dstPeer, err := pe.getPeer(dst)
	if err != nil {
		return res, err
	}
	allowedConns, err := pe.AllAllowedConnectionsBetweenPeers(srcPeer.(Peer), dstPeer.(Peer))
	return allowedConns.(*k8sConnectionSetWrapper).ConnectionSet(), err
}
