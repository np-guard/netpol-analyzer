/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package eval

import (
	"errors"
	"net"
	"strings"

	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/np-guard/models/pkg/netset"

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

func (pe *PolicyEngine) convertPeerToPodPeer(peer Peer) (*k8s.PodPeer, error) {
	var podObj *k8s.Pod
	var podNamespace *k8s.Namespace
	var err error
	switch currentPeer := peer.(type) {
	case *k8s.WorkloadPeer:
		podObj = currentPeer.Pod
		podNamespace, err = pe.getPeerNamespaceObject(podObj)
	default: // should not get here
		return nil, errors.New(netpolerrors.InvalidPeerErrStr(peer.String()))
	}
	if err != nil {
		return nil, err
	}
	podPeer := &k8s.PodPeer{Pod: podObj, NamespaceObject: podNamespace}
	return podPeer, nil
}

func (pe *PolicyEngine) getPeerNamespaceObject(podObj *k8s.Pod) (*k8s.Namespace, error) {
	// if this is a representative peer which is not in a real namespace return nil;
	// PolicyEngine does not contain representative namespaces.
	if podObj.Namespace == "" && podObj.IsPodRepresentative() {
		return nil, nil
	}
	// else , should have the namespace of the pod in policy-engine
	namespaceObj, ok := pe.namespacesMap[podObj.Namespace]
	if !ok {
		return nil, errors.New(netpolerrors.MissingNamespaceErrStr(podObj.Namespace, podObj.Name))
	}
	return namespaceObj, nil
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
		// assuming dstPeer is WorkloadPeer/RepresentativePeer, should be converted to k8s.Peer
		dstPodPeer, err := pe.convertPeerToPodPeer(dstPeer)
		if err != nil {
			return nil, err
		}
		return pe.allAllowedConnectionsBetweenPeers(srcPeer, dstPodPeer)
	}
	if dstPeer.IsPeerIPType() && !srcPeer.IsPeerIPType() {
		// assuming srcPeer is WorkloadPeer/RepresentativePeer, should be converted to k8s.Peer
		srcPodPeer, err := pe.convertPeerToPodPeer(srcPeer)
		if err != nil {
			return nil, err
		}
		return pe.allAllowedConnectionsBetweenPeers(srcPodPeer, dstPeer)
	}
	if !dstPeer.IsPeerIPType() && !srcPeer.IsPeerIPType() {
		// assuming srcPeer and dstPeer are WorkloadPeer/RepresentativePeer, should be converted to k8s.Peer
		srcPodPeer, err := pe.convertPeerToPodPeer(srcPeer)
		if err != nil {
			return nil, err
		}
		dstPodPeer, err := pe.convertPeerToPodPeer(dstPeer)
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
// allowed conns are computed considering all the available resources of k8s network policy api:
// admin-network-policies, network-policies and baseline-admin-network-policies
func (pe *PolicyEngine) allAllowedConnectionsBetweenPeers(srcPeer, dstPeer Peer) (*common.ConnectionSet, error) {
	srcK8sPeer := srcPeer.(k8s.Peer)
	dstK8sPeer := dstPeer.(k8s.Peer)
	var res *common.ConnectionSet
	var err error
	// cases where any connection is always allowed
	if isPodToItself(srcK8sPeer, dstK8sPeer) || isPeerNodeIP(srcK8sPeer, dstK8sPeer) || isPeerNodeIP(dstK8sPeer, srcK8sPeer) {
		return common.MakeConnectionSet(true), nil
	}
	// egress: get egress allowed connections between the src and dst by
	// walking through all k8s egress policies capturing the src;
	// evaluating first ANPs then NPs and finally the BANP
	res, err = pe.allAllowedXgressConnections(srcK8sPeer, dstK8sPeer, false)
	if err != nil {
		return nil, err
	}
	if res.IsEmpty() {
		return res, nil
	}
	// ingress: get ingress allowed connections between the src and dst by
	// walking through all k8s ingress policies capturing the dst;
	// evaluating first ANPs then NPs and finally the BANP
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
func (pe *PolicyEngine) getPoliciesSelectingPod(peer k8s.Peer, direction netv1.PolicyType) ([]*k8s.NetworkPolicy, error) {
	res := []*k8s.NetworkPolicy{}
	if peer.PeerType() == k8s.IPBlockType {
		return res, nil // empty list since netpols may select only pods
	}
	p := peer.(*k8s.PodPeer).Pod
	netpols := pe.netpolsMap[p.Namespace]
	for _, policy := range netpols {
		selects, err := policy.Selects(p, direction)
		if err != nil {
			return nil, err
		}
		if selects {
			res = append(res, policy)
		}
	}
	if pe.exposureAnalysisFlag && len(res) > 0 {
		p.UpdatePodXgressProtectedFlag(direction == netv1.PolicyTypeIngress)
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
		netpols, err = pe.getPoliciesSelectingPod(dst, netv1.PolicyTypeIngress)
	} else {
		netpols, err = pe.getPoliciesSelectingPod(src, netv1.PolicyTypeEgress)
	}
	if err != nil {
		return false, err
	}

	if len(netpols) == 0 { // no networkPolicy captures the relevant pod on the required direction
		return true, nil // all connections allowed
	}

	// iterate relevant network policies (that capture the required pod)
	for _, policy := range netpols {
		// if isIngress: check for ingress rules that capture src within 'from'
		// if not isIngress: check for egress rules that capture dst within 'to'
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

// isPeerNodeIP returns true if peer1 is an IP address of a node and peer2 is a pod on that node
func isPeerNodeIP(peer1, peer2 k8s.Peer) bool {
	if peer2.PeerType() == k8s.PodType && peer1.PeerType() == k8s.IPBlockType {
		ip2, err := netset.IPBlockFromIPAddress(peer2.GetPeerPod().HostIP)
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
		peerIPBlock, err := netset.IPBlockFromCidr(p)
		if err != nil {
			return nil, err
		}
		return &k8s.IPBlockPeer{IPBlock: peerIPBlock}, nil
	}
	// check if input peer is an ip address
	if net.ParseIP(p) != nil {
		peerIPBlock, err := netset.IPBlockFromIPAddress(p)
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
			nsObj, ok := pe.namespacesMap[namespaceStr]
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
// currently used only for testing (computations based on all policy resources (e.g. ANP, NP & BANP))
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
	switch currentPeer := peer.(type) {
	case *k8s.IPBlockPeer:
		return nil
	case *k8s.WorkloadPeer:
		return currentPeer.Pod.PodExposedTCPConnections()
	case *k8s.PodPeer:
		return currentPeer.Pod.PodExposedTCPConnections()
	default:
		return nil
	}
}

// allAllowedXgressConnections: returns the allowed connections from srcPeer to dstPeer on the
// given direction (ingress/egress)
// allowed conns are computed by walking through all the available resources of k8s network policy api:
// admin-network-policies, network-policies and baseline-admin-network-policies;
// considering the precedence of each policy
func (pe *PolicyEngine) allAllowedXgressConnections(src, dst k8s.Peer, isIngress bool) (allowedConns *common.ConnectionSet, err error) {
	// first get allowed xgress conn between the src and dst from the ANPs
	// note that:
	// - anpConns may contain allowed, denied or/and passed connections
	// - anpCaptured is true iff there is at least one rule in the input ANPs that captures both src and dst;
	// because anp rules are read as is and don't contain any implicit isolation effects for the Pods selected by the AdminNetworkPolicy.
	anpConns, anpCaptured, err := pe.getAllAllowedXgressConnectionsFromANPs(src, dst, isIngress)
	if err != nil {
		return nil, err
	}
	// optimization: if all the conns between src and dst were determined by the ANPs : return the allowed conns
	if anpCaptured && anpConns.DeterminesAllConns() {
		return anpConns.AllowedConns, nil
	}
	// second get the allowed xgress conns between the src and dst from the netpols
	// note that :
	// - npConns contains only allowed connections
	// - npCaptured is true iff there are policies selecting either src or dst based on the checked direction (ingress/ egress)
	npConns, npCaptured, err := pe.getAllAllowedXgressConnsFromNetpols(src, dst, isIngress)
	if err != nil {
		return nil, err
	}

	// compute the allowed connections on the given direction considering the which policies captured the xgress connection
	// and precedence of each policy type:
	switch npCaptured {
	case true: // npCaptured
		if !anpCaptured { // npCaptured && !anpCaptured
			// only NPs capture the peers, return allowed conns from netpols
			return npConns.AllowedConns, nil
		}
		// else: npCaptured && anpCaptured
		// if conns between src and dst were captured by both the admin-network-policies and by network-policies
		// collect conns:
		// - traffic that was allowed or denied by ANPs will not be affected by the netpol conns.
		// - traffic that has no match in ANPs but allowed by NPs is added to allowed conns.
		// - pass conns from ANPs, are determined by NPs conns;
		// note that allowed conns by netpols, imply deny on other traffic;
		// so ANPs.pass conns which intersect with NPs.allowed are added to allowed conns result;
		// other pass conns (which don't intersect with NPs allowed conns) are not allowed implicitly.
		anpConns.CollectAllowedConnsFromNetpols(npConns)
		return anpConns.AllowedConns, nil
	default: // !npCaptured - netpols don't capture the connections between src and dst - delegate to banp
		// get default xgress connection between src and dst from the BANP/ system-default;
		// note that :
		// - if there is no banp in the input resources, then default conns is system-default which is allow-all
		// - if the banp captures the xgress between src and dst; then defaultConns may contain allowed and denied conns
		defaultConns, err := pe.getXgressDefaultConns(src, dst, isIngress)
		if err != nil {
			return nil, err
		}
		// possible cases :
		// 1. ANPs capture the peers, netpols don't , return the allowed conns from ANPs considering default conns (& BANP)
		// 2. only BANP captures conns between the src and dst
		// 3. only default conns (no ANPs, nor BANP)
		// then collect conns from banp (or system-default):
		// this also determines what happens on traffic (ports) which are not mentioned in the (B)ANPs;
		// since (B)ANP rules are read as is only.
		anpConns.CollectConnsFromBANP(defaultConns)
		return anpConns.AllowedConns, nil
	}
}

// analyzing network-policies for conns between peers (object kind == NetworkPolicy):

// getAllAllowedXgressConnsFromNetpols returns if connections from src to dst are captured by network policies on given direction,
// if yes, returns also the set of allowed connections from src to dst on given direction(ingress/egress), by network policies rules.
// also checks and updates if a src is exposed to all namespaces on egress or dst is exposed to all namespaces cluster on ingress
// note that network-policies connections represent only allowed conns.
// note that: if there are policies selecting src (on egress) or dst (on ingress), then the xgress connection is captured;
// since NetworkPolicy rules implicitly deny unmentioned connections.
func (pe *PolicyEngine) getAllAllowedXgressConnsFromNetpols(src, dst k8s.Peer, isIngress bool) (policiesConns *k8s.PolicyConnections,
	captured bool, err error) {
	// relevant policies: policies that capture dst if isIngress, else policies that capture src
	var netpols []*k8s.NetworkPolicy
	if isIngress {
		// note that: if dst is an IPBlock peer, then "getPoliciesSelectingPod" will return 0 netpols;
		// since netpols may not select IPs; and then the connection will be determined as system-default
		// allow-all in a later check
		// i.e. the if dst.PeerType() == k8s.IPBlockType is deprecated
		// so this connection is determined later by system-default (which is allow all)
		netpols, err = pe.getPoliciesSelectingPod(dst, netv1.PolicyTypeIngress)
	} else {
		// note that if src is an IPBlock Peer, then "getPoliciesSelectingPod" will return 0 netpols;
		// so this connection is determined later by system-default (which is allow all)
		netpols, err = pe.getPoliciesSelectingPod(src, netv1.PolicyTypeEgress)
	}
	if err != nil {
		return nil, false, err
	}

	if len(netpols) == 0 {
		// if the given direction is not capturing the connection between src and dst,
		// this will be ignored and skipped so allowed conns will be determined later by BANP, or default (allow-all)
		return nil, false, nil
	}
	// connections between src and dst are captured by network-policies
	allowedConns := common.MakeConnectionSet(false)

	// iterate relevant network policies (that capture the required pod)
	for _, policy := range netpols {
		// determine policy's allowed connections between the peers for the direction
		// if isIngress: check for ingress rules that capture src within 'from'
		// if not isIngress: check for egress rules that capture dst within 'to'
		// collect the allowed connectivity from the relevant rules into allowedConns
		policyAllowedConnectionsPerDirection, err := pe.determineAllowedConnsPerDirection(policy, src, dst, isIngress)
		if err != nil {
			return nil, false, err
		}
		// in case of exposure-analysis: update cluster wide exposure data for relevant pod
		if pe.exposureAnalysisFlag {
			updatePeerXgressClusterWideExposure(policy, src, dst, isIngress)
		}
		allowedConns.Union(policyAllowedConnectionsPerDirection)
	}
	// putting the result in policiesConns object to be compared with conns allowed by ANP/BANP later
	policiesConns = k8s.NewPolicyConnections()
	policiesConns.AllowedConns = allowedConns
	return policiesConns, true, nil
}

// determineAllowedConnsPerDirection returns the policy's allowed connections between the
// peers in the given direction
func (pe *PolicyEngine) determineAllowedConnsPerDirection(policy *k8s.NetworkPolicy, src, dst k8s.Peer,
	isIngress bool) (*common.ConnectionSet, error) {
	if isIngress {
		// get ingress allowed conns between src and dst
		switch {
		case policy.IngressPolicyExposure.ExternalExposure.AllowAll:
			return policy.IngressPolicyExposure.ExternalExposure, nil
		case policy.IngressPolicyExposure.ClusterWideExposure.AllowAll && src.PeerType() == k8s.PodType:
			return policy.IngressPolicyExposure.ClusterWideExposure, nil
		default:
			return policy.GetIngressAllowedConns(src, dst)
		}
	}
	// else get egress allowed conns between src and dst
	switch {
	case policy.EgressPolicyExposure.ExternalExposure.AllowAll:
		return policy.EgressPolicyExposure.ExternalExposure, nil
	case policy.EgressPolicyExposure.ClusterWideExposure.AllowAll && dst.PeerType() == k8s.PodType:
		return policy.EgressPolicyExposure.ClusterWideExposure, nil
	default:
		return policy.GetEgressAllowedConns(dst)
	}
}

// updatePeerXgressClusterWideExposure updates the cluster-wide exposure of the pod which is selected by input policy.
// used only when exposure-analysis is active
func updatePeerXgressClusterWideExposure(policy *k8s.NetworkPolicy, src, dst k8s.Peer, isIngress bool) {
	if isIngress {
		// policy selecting dst (dst pod is real)
		// update its ingress entire cluster connection relying on policy data
		dst.GetPeerPod().UpdatePodXgressExposureToEntireClusterData(policy.IngressPolicyExposure.ClusterWideExposure, isIngress)
	} else {
		// policy selecting src
		// update its egress entire cluster connection relying on policy data
		src.GetPeerPod().UpdatePodXgressExposureToEntireClusterData(policy.EgressPolicyExposure.ClusterWideExposure, isIngress)
	}
}

// analyzing admin-network-policies for conns between peers (object kind == AdminNetworkPolicy):

// getAllAllowedXgressConnectionsFromANPs returns the connections from src to dst on give direction (ingress/egress)
// by analyzing admin network policies rules;
// and whether the connection between the src and dst was captured by admin-network-policies' rules.
// note that:
// - ANP connections may be allowed, passed and denied
// - a connection between src and dst is captured by an ANP iff there is an xgress rule capturing both peers, since
// AdminNetworkPolicy rules should be read as-is, i.e. there will not be any implicit isolation effects for
// the Pods selected by the AdminNetworkPolicy, as opposed to implicit deny NetworkPolicy rules imply.
func (pe *PolicyEngine) getAllAllowedXgressConnectionsFromANPs(src, dst k8s.Peer, isIngress bool) (policiesConns *k8s.PolicyConnections,
	captured bool, err error) {
	policiesConns = k8s.NewPolicyConnections()
	// iterate the sorted admin network policies in order to compute the allowed, pass, and denied xgress connections between the peers
	// from the admin netpols capturing the src (if !isIngress)/ capturing the dst (if isIngress true).
	// connections are computed considering ANPs priorities (rules of an ANP with lower priority take precedence on other ANPs rules)
	// and rules ordering in single ANP (coming first takes precedence).
	for _, anp := range pe.sortedAdminNetpols {
		singleANPConns := k8s.NewPolicyConnections()
		// collect the allowed, pass, and denied connectivity from the relevant rules into policiesConns
		if !isIngress { // egress
			selectsSrc, err := anp.Selects(src, false)
			if err != nil {
				return nil, false, err
			}
			// if the anp captures the src, get the relevant egress conns between src and dst
			if selectsSrc {
				singleANPConns, err = anp.GetEgressPolicyConns(dst)
				if err != nil {
					return nil, false, err
				}
			}
		} else { // ingress
			selectsDst, err := anp.Selects(dst, true)
			if err != nil {
				return nil, false, err
			}
			// if the anp captures the dst, get the relevant ingress conns (from src to dst)
			if selectsDst {
				singleANPConns, err = anp.GetIngressPolicyConns(src, dst)
				if err != nil {
					return nil, false, err
				}
			}
		}
		if !singleANPConns.IsEmpty() { // the anp is relevant (the xgress connection is captured)
			policiesConns.CollectANPConns(singleANPConns)
		}
	}

	if policiesConns.IsEmpty() { // conns between src and dst were not captured by the adminNetpols, to be determined by netpols/default conns
		return k8s.NewPolicyConnections(), false, nil
	}

	return policiesConns, true, nil
}

// analyzing baseline-admin-network-policy for conns between peers (object kind == BaselineAdminNetworkPolicy):

// getXgressDefaultConns returns the default connections between src and dst on the given direction (ingress/egress);
// considering the existence of a baseline-admin-network-policy
// if there is a BANP in the input resources, it is analyzed; if it captures xgress conns between src and dst,
// then the captured conns are returned.
// if there is no BANP or if the BANP does not capture connections between src and dst, then default allow-all connections is returned.
// - note that the result may contain allowed / denied connections.
func (pe *PolicyEngine) getXgressDefaultConns(src, dst k8s.Peer, isIngress bool) (*k8s.PolicyConnections, error) {
	res := k8s.NewPolicyConnections()
	if pe.baselineAdminNetpol == nil {
		res.AllowedConns = common.MakeConnectionSet(true)
		return res, nil
	}
	if isIngress { // ingress
		selectsDst, err := pe.baselineAdminNetpol.Selects(dst, true)
		if err != nil {
			return nil, err
		}
		// if the banp selects the dst on ingress, get ingress conns
		if selectsDst {
			res, err = pe.baselineAdminNetpol.GetIngressPolicyConns(src, dst)
			if err != nil {
				return nil, err
			}
		}
	} else { // egress (!isIngress)
		selectsSrc, err := pe.baselineAdminNetpol.Selects(src, false)
		if err != nil {
			return nil, err
		}
		// if the banp selects the src on egress, get egress conns
		if selectsSrc {
			res, err = pe.baselineAdminNetpol.GetEgressPolicyConns(dst)
			if err != nil {
				return nil, err
			}
		}
	}
	if res.IsEmpty() { // banp rules didn't capture xgress conn between src and dst, return system-default: allow-all
		res.AllowedConns = common.MakeConnectionSet(true)
	}
	return res, nil
}
