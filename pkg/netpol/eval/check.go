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
// allowed conns are computed considering all policy resources available, admin-network-policies and network-policies
func (pe *PolicyEngine) allAllowedConnectionsBetweenPeers(srcPeer, dstPeer Peer) (*common.ConnectionSet, error) {
	srcK8sPeer := srcPeer.(k8s.Peer)
	dstK8sPeer := dstPeer.(k8s.Peer)
	var err error
	// cases where any connection is always allowed
	if isPodToItself(srcK8sPeer, dstK8sPeer) || isPeerNodeIP(srcK8sPeer, dstK8sPeer) || isPeerNodeIP(dstK8sPeer, srcK8sPeer) {
		return common.MakeConnectionSet(true), nil
	}

	// first get conns between src and dst from AdminNetworkPolicies, unless one peer is IP, skip, since ANPs are a cluster level resources
	anpCaptured := false
	var anpConns *k8s.PolicyConnections
	if dstK8sPeer.PeerType() != k8s.IPBlockType && srcK8sPeer.PeerType() != k8s.IPBlockType {
		// @todo: when supporting the `Networks` field of an egress rule - dst might be IP-block, so this if statement may be changed/removed.
		// ANP "Selects" func returns false for IP subjects anyway (also now this if does not affect the results, @todo should remove now?)
		anpConns, anpCaptured, err = pe.getAllConnsFromAdminNetpols(srcK8sPeer, dstK8sPeer)
		if err != nil {
			return nil, err
		}
	}

	// get conns between src and dst from networkPolicies:
	npAllowedConns, npCaptured, err := pe.getAllAllowedConnsFromNetpols(srcK8sPeer, dstK8sPeer)
	if err != nil {
		return nil, err
	}

	// get default connection between src and dst: (@todo:when supporting BANP, default will be extracted from it/ def : allow all)
	defaultAllowedConns := common.MakeConnectionSet(true) // @todo: type will be changed to *PolicyConnections (in BANP branch)

	// compute the result considering all captured conns
	if !anpCaptured && !npCaptured {
		// if no ANPs nor NPs capturing the peers, return the default allowed conns
		return defaultAllowedConns, nil
	}
	// else, either ANPs capture the peers, or NPs or both
	if !anpCaptured {
		// only netpols capture the peers, return allowed conns from netpols
		return npAllowedConns, nil
	}
	if !npCaptured {
		// only ANPs capture the peers , return the allowed conns from ANPs.
		// passed conns will be determined by the default allowed conns, since no netpols captured the traffic.
		anpConns.UpdateWithOtherLayerConns(defaultAllowedConns)
		return anpConns.AllowedConns, nil
	}
	// both admin-network-policies and network-policies capture the peers
	anpConns.UpdateWithOtherLayerConns(npAllowedConns)
	return anpConns.AllowedConns, nil
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
// currently used only for testing (computations based on all policy resources (e.g. ANP, NP))
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

// analyzing network-policies for conns between peers (object kind == NetworkPolicy):

// getAllAllowedConnsFromNetpols: returns set of allowed connections between src and dst by analyzing the network-policies rules
func (pe *PolicyEngine) getAllAllowedConnsFromNetpols(src, dst k8s.Peer) (allowedConns *common.ConnectionSet, npCaptured bool, err error) {
	var res, ingressRes *common.ConnectionSet
	egressCaptured, ingressCaptured := false, false
	// egress
	res, egressCaptured, err = pe.getAllAllowedXgressConnsFromNetpols(src, dst, false)
	if err != nil {
		return nil, false, err
	}
	if egressCaptured && res.IsEmpty() {
		return res, egressCaptured, nil
	}
	// ingress
	ingressRes, ingressCaptured, err = pe.getAllAllowedXgressConnsFromNetpols(src, dst, true)
	if err != nil {
		return nil, false, err
	}
	res.Intersection(ingressRes)
	return res, ingressCaptured || egressCaptured, nil
}

// getAllAllowedXgressConnsFromNetpols returns the set of allowed connections from src to dst on given
// direction(ingress/egress), by network policies rules
// also checks and updates if a src is exposed to all namespaces on egress or
// dst is exposed to all namespaces cluster on ingress
func (pe *PolicyEngine) getAllAllowedXgressConnsFromNetpols(src, dst k8s.Peer, isIngress bool) (allowedConns *common.ConnectionSet,
	captured bool, err error) {
	// relevant policies: policies that capture dst if isIngress, else policies that capture src
	var netpols []*k8s.NetworkPolicy
	if isIngress {
		if dst.PeerType() == k8s.IPBlockType {
			return common.MakeConnectionSet(true), true, nil // all connections allowed - no restrictions on ingress to externalIP.
			// returning true as captured because other policy resources are clustered only (only netpols may affect conns to and from IPs)
		}
		netpols, err = pe.getPoliciesSelectingPod(dst.GetPeerPod(), netv1.PolicyTypeIngress)
	} else {
		if src.PeerType() == k8s.IPBlockType {
			return common.MakeConnectionSet(true), true, nil // all connections allowed - no restrictions on egress from externalIP
		}
		netpols, err = pe.getPoliciesSelectingPod(src.GetPeerPod(), netv1.PolicyTypeEgress)
	}
	if err != nil {
		return nil, false, err
	}

	if len(netpols) == 0 {
		// default of network-policies is allow all, if both directions not capturing the conn,
		// this will be ignored and skipped so allowed conns will be determined by BANP, or system-default
		return common.MakeConnectionSet(true), false, nil
	}

	allowedConns = common.MakeConnectionSet(false)

	// iterate relevant network policies (that capture the required pod)
	for _, policy := range netpols {
		// determine policy's allowed connections between the peers for the direction
		// if isIngress: check for ingress rules that capture src within 'from'
		// if not isIngress: check for egress rules that capture dst within 'to'
		// collect the allowed connectivity from the relevant rules into allowedConns
		policyAllowedConnectionsPerDirection, err := pe.determineAllowedConnsPerDirection(policy, src, dst, isIngress)
		// in case of exposure-analysis: update cluster wide exposure data for relevant pod
		if pe.exposureAnalysisFlag {
			updatePeerXgressClusterWideExposure(policy, src, dst, isIngress)
		}
		if err != nil {
			return nil, false, err
		}
		allowedConns.Union(policyAllowedConnectionsPerDirection)
	}
	return allowedConns, true, nil
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

// getAllConnsFromAdminNetpols returns the connections from src to dst by analyzing admin network policies rules
func (pe *PolicyEngine) getAllConnsFromAdminNetpols(src, dst k8s.Peer) (policiesConns *k8s.PolicyConnections,
	captured bool, err error) {
	policiesConns = k8s.InitEmptyPolicyConnections()
	// iterate the sorted admin network policies in order to compute the allowed, pass, and denied connections between the peers
	// from the admin netpols capturing the src / dst / both.
	// connections are computed considering ANPs priorities (rules of an ANP with lower priority take precedence on other ANPs rules)
	// and rules ordering in single ANP (coming first takes precedence).
	for _, anp := range pe.sortedAdminNetpols {
		singleANPConns := k8s.InitEmptyPolicyConnections()
		// collect the allowed, pass, and denied connectivity from the relevant rules into policiesConns
		// note that anp may capture both the src and dst (by namespaces field), so both ingress and egress sections might be helpful

		// if the anp captures the src, get the relevant egress conns between src and dst
		selectsSrc, err := anp.Selects(src, false)
		if err != nil {
			return nil, false, err
		}
		if selectsSrc {
			singleANPConns, err = anp.GetEgressPolicyConns(dst)
			if err != nil {
				return nil, false, err
			}
		}
		// if the anp captures the dst, get the relevant ingress conns (from src to dst)
		selectsDst, err := anp.Selects(dst, true)
		if err != nil {
			return nil, false, err
		}
		if selectsDst {
			ingressConns, err := anp.GetIngressPolicyConns(src, dst)
			if err != nil {
				return nil, false, err
			}
			// get the intersection of ingress and egress sections if also the src was captured
			if selectsSrc {
				singleANPConns.AllowedConns.Intersection(ingressConns.AllowedConns)
				singleANPConns.DeniedConns.Union(ingressConns.DeniedConns)
				singleANPConns.PassConns.Union(ingressConns.PassConns)
			} else { // only dst is captured by anp
				singleANPConns = ingressConns
			}
		}
		if !singleANPConns.IsEmpty() { // the anp is relevant (captured at least one of the peers)
			policiesConns.CollectANPConns(singleANPConns)
		}
	}

	if policiesConns.IsEmpty() { // conns between src and dst were not captured by the adminNetpols, to be determined by netpols/default conns
		return nil, false, nil
	}

	return policiesConns, true, nil
}
