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
// allowed conns are computed considering all policy resources available, admin-network-policies and network-policies
func (pe *PolicyEngine) allAllowedConnectionsBetweenPeers(srcPeer, dstPeer Peer) (*common.ConnectionSet, error) {
	srcK8sPeer := srcPeer.(k8s.Peer)
	dstK8sPeer := dstPeer.(k8s.Peer)
	var err error
	// cases where any connection is always allowed
	if isPodToItself(srcK8sPeer, dstK8sPeer) || isPeerNodeIP(srcK8sPeer, dstK8sPeer) || isPeerNodeIP(dstK8sPeer, srcK8sPeer) {
		return common.MakeConnectionSet(true), nil
	}

	// default connection: (@todo:when supporting BANP, default will be extracted from it)
	defaultAllowedConns := common.MakeConnectionSet(true) // default is allowAll conns ,  @todo: type will be changed to *PolicyConnections

	// first get conns from AdminNetworkPolicies:
	// unless one peer is IP, skip, since ANPs are a cluster level resources
	anpCaptured := false
	var anpConns *k8s.PolicyConnections
	if dstK8sPeer.PeerType() != k8s.IPBlockType && srcK8sPeer.PeerType() != k8s.IPBlockType {
		anpConns, anpCaptured, err = pe.getAllConnsFromAdminNetpols(srcK8sPeer, dstK8sPeer)
		if err != nil {
			return nil, err
		}
	}

	// get conns from networkPolicies:
	var npAllowedConns *common.ConnectionSet
	npCaptured := false
	npAllowedConns, npCaptured, err = pe.getAllAllowedConnsFromNetpols(srcK8sPeer, dstK8sPeer)
	if err != nil {
		return nil, err
	}

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

// CheckIfAllowedNew: (connection-set based computation) returns true if the given input connection is
// allowed by network policies
// currently used only for testing
func (pe *PolicyEngine) CheckIfAllowedNew(src, dst, protocol, port string) (bool, error) {
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

// analyzing network-policies for conns between peers (object kind == NetworkPolicy):

// getAllAllowedConnsFromNetpols : returns set of allowed connections between src and dst by analyzing the network-policies rules
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

// analyzing admin-network-policies for conns between peers (object kind == AdminNetworkPolicy):

// getAllConnsFromAdminNetpols returns the connections from src to dst by analyzing admin network policies rules
func (pe *PolicyEngine) getAllConnsFromAdminNetpols(src, dst k8s.Peer) (anpsConns *k8s.PolicyConnections,
	captured bool, err error) {
	// since the priority of policies is critical for computing the conns between peers, we need all admin policies capturing both peers.
	// get all admin policies selecting the dst in Ingress direction
	dstAdminNetpols, err := pe.getAdminNetpolsSelectingPeer(dst, true)
	if err != nil {
		return nil, false, err
	}
	// get all admin policies selecting the src in egress direction
	srcAdminNetpols, err := pe.getAdminNetpolsSelectingPeer(src, false)
	if err != nil {
		return nil, false, err
	}

	if len(dstAdminNetpols) == 0 && len(srcAdminNetpols) == 0 {
		// if there are no admin netpols selecting the peers, returning nil conns,
		// conns will be determined by other policy objects/ default value
		return nil, false, nil
	}

	// admin netpols may select subjects by namespaces, so an ANP may appear in both dstAminNetpols, and srcAdminNetpols.
	// then merging both sets into one unique and sorted by priority list of admin-network-policies.
	adminNetpols, err := getUniqueAndSortedANPsList(dstAdminNetpols, srcAdminNetpols)
	if err != nil {
		return nil, false, err
	}

	policiesConns := k8s.InitEmptyPolicyConnections()
	// iterate the related sorted admin network policies in order to compute the allowed, pass, and denied connections between the peers
	for _, anp := range adminNetpols {
		// collect the allowed, pass, and denied connectivity from the relevant rules into policiesConns
		// note that anp may capture both the src and dst (by namespaces field), so both ingress and egress sections might be helpful

		// if the anp captures the src, get the relevant egress conns between src and dst
		if srcAdminNetpols[anp] {
			policyConnsPerDirection, err := anp.GetEgressPolicyConns(dst)
			if err != nil {
				return nil, false, err
			}
			policiesConns.CollectANPConns(policyConnsPerDirection)
		}
		// if the anp captures the dst, get the relevant ingress conns (from src to dst)
		if dstAdminNetpols[anp] {
			policyConnsPerDirection, err := anp.GetIngressPolicyConns(src, dst)
			if err != nil {
				return nil, false, err
			}
			policiesConns.CollectANPConns(policyConnsPerDirection)
		}
	}

	if policiesConns.IsEmpty() { // conns between src and dst were not captured by the adminNetpols, to be determined by netpols/default conns
		return nil, false, nil
	}

	return policiesConns, true, nil
}

// getAdminNetpolsSelectingPeer returns set of adminNetworkPolicies which select the input peer and have rules on the required direction
func (pe *PolicyEngine) getAdminNetpolsSelectingPeer(peer k8s.Peer, isIngress bool) (map[*k8s.AdminNetworkPolicy]bool, error) {
	res := make(map[*k8s.AdminNetworkPolicy]bool, 0) // set
	for _, anp := range pe.adminNetpolsMap {
		selects, err := anp.Selects(peer, isIngress)
		if err != nil {
			return nil, err
		}
		if selects {
			res[anp] = true
		}
	}
	return res, nil
}

// getUniqueANPsList gets two sets of adminNetpols and merges them into one list with unique ANP objects
func getUniqueAndSortedANPsList(ingressAnps, egressAnps map[*k8s.AdminNetworkPolicy]bool) ([]*k8s.AdminNetworkPolicy, error) {
	res := []*k8s.AdminNetworkPolicy{}
	for key := range ingressAnps {
		res = append(res, key)
	}
	for key := range egressAnps {
		if !ingressAnps[key] {
			res = append(res, key)
		}
	}
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
