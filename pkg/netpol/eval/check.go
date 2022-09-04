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
	"strings"

	netv1 "k8s.io/api/networking/v1"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval/internal/k8s"
)

const (
	separator        = "/"
	defaultNamespace = "default"
)

// getNetworkPolicies returns a list of netpols on the input namespace
func getNetworkPolicies(namespace string) []*k8s.NetworkPolicy {
	res := []*k8s.NetworkPolicy{}
	netpols, ok := netpolsMap[namespace]
	if ok {
		res = netpols
	}
	return res
}

// TODO: consider caching: for each pod and direction, test set of policies that are selecting it
// getPoliciesSelectingPod returns a list of policies that select the input pod on the required direction (ingress/egress)
func getPoliciesSelectingPod(p *k8s.Pod, direction netv1.PolicyType) []*k8s.NetworkPolicy {
	netpols := getNetworkPolicies(p.Namespace)
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
func allowedXgressConnection(src, dst k8s.Peer, isIngress bool, protocol, port string) (bool, error) {
	// relevant policies: policies that capture dst if isIngress, else policies that capture src
	var netpols []*k8s.NetworkPolicy
	if isIngress {
		if dst.PeerType == k8s.Iptype {
			return true, nil // all connections allowed - no restrictions on ingress to externalIP
		}
		netpols = getPoliciesSelectingPod(dst.Pod, netv1.PolicyTypeIngress)
	} else {
		if src.PeerType == k8s.Iptype {
			return true, nil // all connections allowed - no restrictions on egress from externalIP
		}
		netpols = getPoliciesSelectingPod(src.Pod, netv1.PolicyTypeEgress)
	}

	if len(netpols) == 0 {
		return true, nil // all connections allowed - no networkpolicy captures the relevant pod on the required direction
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

// AllallowedXgressConnections returns the set of allowed connections from src to dst on given
// direction(ingress/egress), by network policies rules
func AllallowedXgressConnections(src, dst k8s.Peer, isIngress bool) k8s.ConnectionSet {
	// relevant policies: policies that capture dst if isIngress, else policies that capture src
	var netpols []*k8s.NetworkPolicy
	if isIngress {
		if dst.PeerType == k8s.Iptype {
			return k8s.MakeConnectionSet(true) // all connections allowed - no restrictions on ingress to externalIP
		}
		netpols = getPoliciesSelectingPod(dst.Pod, netv1.PolicyTypeIngress)
	} else {
		if src.PeerType == k8s.Iptype {
			return k8s.MakeConnectionSet(true) // all connections allowed - no restrictions on egress from externalIP
		}
		netpols = getPoliciesSelectingPod(src.Pod, netv1.PolicyTypeEgress)
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
	return peer2.PeerType == k8s.PodType && peer1.PeerType == k8s.Iptype && peer2.Pod.HostIP == peer1.IP
}

func getPeer(p string) (k8s.Peer, error) {
	if strings.Contains(p, separator) { // pod name
		podObj := GetPod(p)
		if podObj != nil {
			res := k8s.Peer{PeerType: k8s.PodType, Pod: podObj}
			namespaceStr := podObj.Namespace
			if namespaceStr == "" {
				namespaceStr = defaultNamespace
			}
			nsObj, ok := namspacesMap[namespaceStr]
			if !ok {
				return k8s.Peer{}, errors.New("could not find peer namespace")
			}
			res.Namespace = nsObj
			return res, nil
		}
		return k8s.Peer{}, errors.New("could not find peer")
	}
	// assuming p is an ip address
	return k8s.Peer{PeerType: k8s.Iptype, IP: p}, nil
}

// checkIfAllowed returns true if the given input connection is allowed by network policies
func CheckIfAllowed(src, dst, protocol, port string) (bool, error) {
	// retrieve source (and destination) pods and store
	// retrieve source (and destination) namespaces and store
	// retrieve all network policies in given namespaces (source, optionally destination)
	// convert source and destination into 5-tuple (protcocol, source ip:port, dest ip:port)
	// call to evaluate network policies on 5-tuple

	srcPeer, err := getPeer(src)
	if err != nil {
		return false, err
	}
	dstPeer, err := getPeer(dst)
	if err != nil {
		return false, err
	}
	// cases where any connection is always allowed
	if srcPeer == dstPeer || isPeerNodeIP(srcPeer, dstPeer) || isPeerNodeIP(dstPeer, srcPeer) {
		return true, nil
	}

	egressRes, err := allowedXgressConnection(srcPeer, dstPeer, false, protocol, port)
	if err != nil {
		return false, err
	}
	if !egressRes {
		return false, nil
	}
	ingressRes, err := allowedXgressConnection(srcPeer, dstPeer, true, protocol, port)
	if err != nil {
		return false, err
	}
	return ingressRes, nil
}

func CheckIfAllowedNew(src, dst, protocol, port string) (bool, error) {
	allowedConns, err := AllAllowedConnections(src, dst)
	if err != nil {
		return false, err
	}
	return allowedConns.Contains(port, protocol), nil
}

func AllAllowedConnections(src, dst string) (k8s.ConnectionSet, error) {
	res := k8s.ConnectionSet{}
	srcPeer, err := getPeer(src)
	if err != nil {
		return res, err
	}
	dstPeer, err := getPeer(dst)
	if err != nil {
		return res, err
	}
	// cases where any connection is always allowed
	if srcPeer == dstPeer || isPeerNodeIP(srcPeer, dstPeer) || isPeerNodeIP(dstPeer, srcPeer) {
		return k8s.MakeConnectionSet(true), nil
	}
	// egress
	res = AllallowedXgressConnections(srcPeer, dstPeer, false)
	if res.IsEmpty() {
		return res, nil
	}
	// ingress
	res.Intersection(AllallowedXgressConnections(srcPeer, dstPeer, true))
	return res, nil
}
