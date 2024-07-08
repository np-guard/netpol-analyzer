/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package eval

import (
	"errors"
	"net"
	"sort"
	"strings"

	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/np-guard/models/pkg/ipblock"

	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval/internal/k8s"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
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

func (pe *PolicyEngine) convertWorkloadPeerToPodPeer(peer Peer) (*k8s.PodPeer, error) {
	if workloadPeer, ok := peer.(*k8s.WorkloadPeer); ok {
		podNamespace, ok := pe.namspacesMap[workloadPeer.Pod.Namespace]
		if !ok {
			return nil, errors.New(netpolerrors.MissingNamespaceErrStr(workloadPeer.String()))
		}
		podPeer := &k8s.PodPeer{Pod: workloadPeer.Pod, NamespaceObject: podNamespace}
		return podPeer, nil
	}
	return nil, errors.New(netpolerrors.NotPeerErrStr(peer.String()))
}

// for connectivity considerations, when requesting allowed connections between 2 workload peers which are the same,
// looking for 2 different pod instances, if exist (to avoid the trivial case of connectivity from pod to itself)
func (pe *PolicyEngine) changePodPeerToAnotherPodObject(peer *k8s.PodPeer) {
	// look for another pod, different from peer.Pod, with the same owner
	for _, pod := range pe.podsMap {
		if pod.Namespace == peer.Pod.Namespace && pod.Name != peer.Pod.Name && pod.Owner.Name == peer.Pod.Owner.Name {
			peer.Pod = pod
			break
		}
	}
}

// AllAllowedConnectionsBetweenWorkloadPeers returns the allowed connections from srcPeer to dstPeer,
// expecting that srcPeer and dstPeer are in level of workloads (WorkloadPeer)
func (pe *PolicyEngine) AllAllowedConnectionsBetweenWorkloadPeers(srcPeer, dstPeer Peer) (*common.ConnectionSet, error) {
	if srcPeer.IsPeerIPType() && !dstPeer.IsPeerIPType() {
		// assuming dstPeer is WorkloadPeer, should be converted to k8s.Peer
		dstPodPeer, err := pe.convertWorkloadPeerToPodPeer(dstPeer)
		if err != nil {
			return nil, err
		}
		return pe.allAllowedConnectionsBetweenPeers(srcPeer, dstPodPeer)
	}
	if dstPeer.IsPeerIPType() && !srcPeer.IsPeerIPType() {
		// assuming srcPeer is WorkloadPeer, should be converted to k8s.Peer
		srcPodPeer, err := pe.convertWorkloadPeerToPodPeer(srcPeer)
		if err != nil {
			return nil, err
		}
		return pe.allAllowedConnectionsBetweenPeers(srcPodPeer, dstPeer)
	}
	if !dstPeer.IsPeerIPType() && !srcPeer.IsPeerIPType() {
		// assuming srcPeer and dstPeer are WorkloadPeer, should be converted to k8s.Peer
		srcPodPeer, err := pe.convertWorkloadPeerToPodPeer(srcPeer)
		if err != nil {
			return nil, err
		}
		dstPodPeer, err := pe.convertWorkloadPeerToPodPeer(dstPeer)
		if err != nil {
			return nil, err
		}
		// if src and dst are the same workload peer, their conversion to pods should be of different pods
		// (if owner has more than 1 instances)
		if srcPeer.String() == dstPeer.String() {
			pe.changePodPeerToAnotherPodObject(dstPodPeer)
		}
		return pe.allAllowedConnectionsBetweenPeers(srcPodPeer, dstPodPeer)
	}
	return nil, errors.New(netpolerrors.BothSrcAndDstIPsErrStr(srcPeer.String(), dstPeer.String()))
}

// allAllowedConnectionsBetweenPeers: returns the allowed connections from srcPeer to dstPeer
// expecting that srcPeer and dstPeer are in level of pods (PodPeer)
func (pe *PolicyEngine) allAllowedConnectionsBetweenPeers(srcPeer, dstPeer Peer) (*common.ConnectionSet, error) {
	srcK8sPeer := srcPeer.(k8s.Peer)
	dstK8sPeer := dstPeer.(k8s.Peer)
	var res *common.ConnectionSet
	var err error
	// cases where any connection is always allowed
	if isPodToItself(srcK8sPeer, dstK8sPeer) || isPeerNodeIP(srcK8sPeer, dstK8sPeer) || isPeerNodeIP(dstK8sPeer, srcK8sPeer) {
		return common.MakeConnectionSet(true), nil
	}
	// egress
	res, err = pe.allAllowedXgressConnections(srcK8sPeer, dstK8sPeer, false)
	if err != nil {
		return nil, err
	}
	if res.IsEmpty() {
		return res, nil
	}
	// ingress
	ingressRes, err := pe.allAllowedXgressConnections(srcK8sPeer, dstK8sPeer, true)
	if err != nil {
		return nil, err
	}
	res.Intersection(ingressRes)
	return res, nil
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
func (pe *PolicyEngine) getPoliciesSelectingPod(p *k8s.Pod, direction netv1.PolicyType) ([]*k8s.NetworkPolicy, error) {
	netpols := pe.netpolsMap[p.Namespace]
	res := []*k8s.NetworkPolicy{}
	for _, policy := range netpols {
		selects, err := policy.Selects(p, direction)
		if err != nil {
			return nil, err
		}
		if selects {
			res = append(res, policy)
		}
	}
	return res, nil
}

// allowedXgressConnections returns true if the given connection from src to dst on given direction(ingress/egress)
// is allowed by network policies rules
func (pe *PolicyEngine) allowedXgressConnection(src, dst k8s.Peer, isIngress bool, protocol, port string) (bool, error) {
	// relevant policies: policies that capture dst if isIngress, else policies that capture src
	var err error
	var netpols []*k8s.NetworkPolicy
	if isIngress {
		if dst.PeerType() == k8s.IPBlockType {
			return true, nil // all connections allowed - no restrictions on ingress to externalIP
		}
		netpols, err = pe.getPoliciesSelectingPod(dst.(*k8s.PodPeer).Pod, netv1.PolicyTypeIngress)
	} else {
		if src.PeerType() == k8s.IPBlockType {
			return true, nil // all connections allowed - no restrictions on egress from externalIP
		}
		netpols, err = pe.getPoliciesSelectingPod(src.(*k8s.PodPeer).Pod, netv1.PolicyTypeEgress)
	}
	if err != nil {
		return false, err
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

// @todo: check correctness by adding more complicated tests : current implementation first analyze egress conns
// between src and dst (from ANPs and NPs)
// then analyzes ingress conns on ANPs and NPs and finally the intersection of ingress and egress allowed conns is returned

// allAllowedXgressConnections returns the set of allowed connections from src to dst on given
// direction(ingress/egress), by admin-network-policies and network-policies rules
func (pe *PolicyEngine) allAllowedXgressConnections(src, dst k8s.Peer, isIngress bool) (allowedConns *common.ConnectionSet, err error) {
	// default conns from IPs  (on egress) or to IPs (on ingress)
	if isIngress {
		if dst.PeerType() == k8s.IPBlockType {
			return common.MakeConnectionSet(true), nil // all connections allowed - no restrictions on ingress to externalIP
		}
	} else {
		if src.PeerType() == k8s.IPBlockType {
			return common.MakeConnectionSet(true), nil // all connections allowed - no restrictions on egress from externalIP
		}
	}

	defaultAllowedConns := common.MakeConnectionSet(true) // default is allowAll conns (@todo:if there is an BANP,
	// default will be extracted from it, @todo: this will be changed to *PolicyConnections)

	anpConns, anpCaptured, err := pe.getAllAllowedXgressConnsFromAdminNetpols(src, dst, isIngress)
	if err != nil {
		return nil, err
	}
	// @todo : change returned value from getAllAllowedXgressConnsFromNetpols to PolicyConnections (with only allowedConns)
	npAllowedConns, npCaptured, err := pe.getAllAllowedXgressConnsFromNetpols(src, dst, isIngress)
	if err != nil {
		return nil, err
	}

	if !anpCaptured && !npCaptured { // if no ANPs nor NPs capturing the peers, return the default allowed conns
		return defaultAllowedConns, nil
	}
	// else, either ANPs capture the peers, or NPs or both
	if !anpCaptured { // only netpols capture the peers, return allowed conns from netpols
		return npAllowedConns, nil
	}
	if !npCaptured { // only ANPs capture the peers , return the allowed conns from ANPs
		anpConns.UpdateWithOtherLayerConns(defaultAllowedConns)
		return anpConns.AllowedConns, nil
	}
	// both admin-network-policies and network-policies capture the peers
	anpConns.UpdateWithOtherLayerConns(npAllowedConns)
	return anpConns.AllowedConns, nil
}

// isPeerNodeIP returns true if peer1 is an IP address of a node and peer2 is a pod on that node
func isPeerNodeIP(peer1, peer2 k8s.Peer) bool {
	if peer2.PeerType() == k8s.PodType && peer1.PeerType() == k8s.IPBlockType {
		ip2, err := ipblock.FromIPAddress(peer2.GetPeerPod().HostIP)
		if err != nil {
			return peer1.GetPeerIPBlock().Equal(ip2)
		}
	}
	return false
}

// func isPeerNodeIP(peer1, peer2 k8s.Peer) bool {
// 	if peer2.PeerType() == k8s.PodType && peer1.PeerType() == k8s.IPBlockType {
// 		return net.ParseIP(peer2.GetPeerPod().HostIP) != nil
// 	}
// 	return false
// }

func isPodToItself(peer1, peer2 k8s.Peer) bool {
	return peer1.PeerType() == k8s.PodType && peer2.PeerType() == k8s.PodType &&
		peer1.GetPeerPod().Name == peer2.GetPeerPod().Name && peer1.GetPeerPod().Namespace == peer2.GetPeerPod().Namespace
}

func (pe *PolicyEngine) getPeer(p string) (k8s.Peer, error) {
	// check if input peer is cidr
	if _, _, err := net.ParseCIDR(p); err == nil {
		peerIPBlock, err := ipblock.FromCidr(p)
		if err != nil {
			return nil, err
		}
		return &k8s.IPBlockPeer{IPBlock: peerIPBlock}, nil
	}
	// check if input peer is an ip address
	if net.ParseIP(p) != nil {
		peerIPBlock, err := ipblock.FromIPAddress(p)
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
				return nil, errors.New(netpolerrors.NotFoundNamespace)
			}
			res.NamespaceObject = nsObj
			return res, nil
		}
		return nil, errors.New(netpolerrors.NotFoundPeerErrStr(p))
	}
	return nil, errors.New(netpolerrors.InvalidPeerErrStr(p))
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
func (pe *PolicyEngine) allAllowedConnections(src, dst string) (*common.ConnectionSet, error) {
	srcPeer, err := pe.getPeer(src)
	if err != nil {
		return nil, err
	}
	dstPeer, err := pe.getPeer(dst)
	if err != nil {
		return nil, err
	}
	allowedConns, err := pe.allAllowedConnectionsBetweenPeers(srcPeer.(Peer), dstPeer.(Peer))
	return allowedConns, err
}

// GetPeerExposedTCPConnections returns the tcp connection (ports) exposed by a workload/pod peer
func GetPeerExposedTCPConnections(peer Peer) *common.ConnectionSet {
	switch currPeer := peer.(type) {
	case *k8s.IPBlockPeer:
		return nil
	case *k8s.WorkloadPeer:
		return currPeer.Pod.PodExposedTCPConnections()
	case *k8s.PodPeer:
		return currPeer.Pod.PodExposedTCPConnections()
	default:
		return nil
	}
}

// getAllAllowedXgressConnsFromNetpols returns the set of allowed connections from src to dst on given
// direction(ingress/egress), by network policies rules (object kind == NetworkPolicy)
func (pe *PolicyEngine) getAllAllowedXgressConnsFromNetpols(src, dst k8s.Peer, isIngress bool) (allowedConns *common.ConnectionSet,
	captured bool, err error) {
	// note that if isIngress : dst is not an IP , and if !isIngress src can not be IP (case already handled)
	// relevant policies: policies that capture dst if isIngress, else policies that capture src
	var netpols []*k8s.NetworkPolicy
	if isIngress {
		netpols, err = pe.getPoliciesSelectingPod(dst.GetPeerPod(), netv1.PolicyTypeIngress)
	} else {
		netpols, err = pe.getPoliciesSelectingPod(src.GetPeerPod(), netv1.PolicyTypeEgress)
	}
	if err != nil {
		return nil, false, err
	}

	if len(netpols) == 0 {
		//  no network policy captures the relevant pod on the required direction, returning nil conns,
		// conns will be determined by other policy objects/ default value
		return nil, false, nil
	}

	allowedConns = common.MakeConnectionSet(false)

	// iterate relevant network policies (that capture the required pod)
	for _, policy := range netpols {
		// if isIngress: check for ingress rules that capture src within 'from'
		// if not isIngress: check for egress rules that capture dst within 'to'
		// collect the allowed connectivity from the relevant rules into allowedConns
		var policyAllowedConnectionsPerDirection *common.ConnectionSet
		var err error
		if isIngress {
			policyAllowedConnectionsPerDirection, err = policy.GetIngressAllowedConns(src, dst)
		} else {
			policyAllowedConnectionsPerDirection, err = policy.GetEgressAllowedConns(dst)
		}
		if err != nil {
			return nil, false, err
		}
		allowedConns.Union(policyAllowedConnectionsPerDirection)
	}
	return allowedConns, true, nil
}

// analyzing admin network policies for conns between peers

// getAllAllowedXgressConnsFromAdminNetpols returns the set of allowed connections from src to dst on given
// direction(ingress/egress), by admin network policies rules (object kind == AdminNetworkPolicy)
func (pe *PolicyEngine) getAllAllowedXgressConnsFromAdminNetpols(src, dst k8s.Peer, isIngress bool) (anpsConns *k8s.PolicyConnections,
	captured bool, err error) {
	var adminNetpols []*k8s.AdminNetworkPolicy
	if isIngress {
		adminNetpols, err = pe.getAdminNetpolsSelectingPeerSortedByPriority(dst, true)
	} else {
		adminNetpols, err = pe.getAdminNetpolsSelectingPeerSortedByPriority(src, false)
	}
	if err != nil {
		return nil, false, err
	}

	if len(adminNetpols) == 0 {
		// if there are no admin netpols selecting the pods, returning nil conns,
		// conns will be determined by other policy objects/ default value
		return nil, false, nil
	}

	policiesConns := k8s.InitEmptyPolicyConnections()
	// iterate the related sorted admin network policies in order to compute the allowed, pass, and denied connections between the peers
	for _, anp := range adminNetpols {
		// if isIngress: check for ingress rules that capture src;
		// if not isIngress: check for egress rules that capture dst;
		// collect the allowed, pass, and denied connectivity from the relevant rules into policiesConns
		var policyConnsPerDirection *k8s.PolicyConnections
		var err error
		if isIngress {
			policyConnsPerDirection, err = anp.GetIngressPolicyConns(src, dst)
		} else {
			policyConnsPerDirection, err = anp.GetEgressPolicyConns(dst)
		}
		if err != nil {
			return nil, false, err
		}
		policiesConns.CollectANPConns(policyConnsPerDirection)
	}
	if policiesConns.IsEmpty() { // conns between src and dst were not captured by the adminNetpols, to be determined by netpols/default conns
		return nil, false, nil
	}
	return policiesConns, true, nil
}

// getAdminNetpolsSelectingPeer returns list of adminNetworkPolicies which select the input peer and have rules on the required direction
func (pe *PolicyEngine) getAdminNetpolsSelectingPeerSortedByPriority(peer k8s.Peer, isIngress bool) ([]*k8s.AdminNetworkPolicy, error) {
	res := []*k8s.AdminNetworkPolicy{}
	for _, anp := range pe.adminNetpolsMap {
		selects, err := anp.Selects(peer, isIngress)
		if err != nil {
			return nil, err
		}
		if selects {
			res = append(res, anp)
		}
	}
	if len(res) == 0 { // no anps selecting the peer
		return res, nil
	}
	// sort ANPs by priority
	return sortAdminNetpolsByPriority(res)
}

// sortAdminNetpolsByPriority sorts the given list of admin-network-policies by priority
func sortAdminNetpolsByPriority(anpList []*k8s.AdminNetworkPolicy) ([]*k8s.AdminNetworkPolicy, error) {
	var err error
	sort.Slice(anpList, func(i, j int) bool {
		if anpList[i].Spec.Priority == anpList[j].Spec.Priority {
			err = errors.New(netpolerrors.SamePriorityErr(anpList[i].Name, anpList[j].Name))
			return false
		}
		if !anpList[i].HasValidPriority() {
			err = errors.New(netpolerrors.PriorityValueErr(anpList[i].Name, anpList[i].Spec.Priority))
			return false
		}
		if !anpList[j].HasValidPriority() {
			err = errors.New(netpolerrors.PriorityValueErr(anpList[j].Name, anpList[j].Spec.Priority))
			return false
		}
		return anpList[i].Spec.Priority < anpList[j].Spec.Priority
	})
	return anpList, err
}
