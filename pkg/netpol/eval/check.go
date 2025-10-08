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
	"github.com/np-guard/netpol-analyzer/pkg/manifests/parser"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval/internal/k8s"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/alerts"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// this file contains methods that return all allowed connections between two peers;
// those funcs are related to the `list` & `diff` commands.

// it also contains inner funcs in `eval` package; used in this file and `check_eval.go`

// convertPeerToPodPeer converts a given workload peer to a PodPeer object.
func (pe *PolicyEngine) convertPeerToPodPeer(peer Peer) (*k8s.PodPeer, error) {
	var podObj *k8s.Pod
	var podNamespace *k8s.Namespace
	var err error
	switch currentPeer := peer.(type) {
	case *k8s.WorkloadPeer:
		podObj = currentPeer.Pod
		podNamespace, err = pe.getPeerNamespaceObject(podObj)
	default: // should not get here
		return nil, errors.New(alerts.InvalidPeerErrStr(peer.String()))
	}
	if err != nil {
		return nil, err
	}
	podPeer := &k8s.PodPeer{Pod: podObj, NamespaceObject: podNamespace}
	return podPeer, nil
}

// getPeerNamespaceObject returns the namespace object for the given pod.
// If the pod is a representative peer, it returns nil,
// Otherwise, it returns the namespace object from the policy engine.
func (pe *PolicyEngine) getPeerNamespaceObject(podObj *k8s.Pod) (*k8s.Namespace, error) {
	// if this is a representative peer which is not in a real namespace return nil;
	// PolicyEngine does not contain representative namespaces.
	if podObj.Namespace == "" && podObj.IsPodRepresentative() {
		return nil, nil
	}
	// else , should have the namespace of the pod in policy-engine
	namespaceObj, ok := pe.namespacesMap[podObj.Namespace]
	if !ok {
		return nil, errors.New(alerts.MissingNamespaceErrStr(podObj.Namespace, podObj.Name))
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
				return nil, errors.New(alerts.NotFoundNamespace)
			}
			res.NamespaceObject = nsObj
			return res, nil
		}
		return nil, errors.New(netpolerrors.NotFoundPeerErrStr(p))
	}
	return nil, errors.New(alerts.InvalidPeerErrStr(p))
}

// GetPeerExposedTCPConnections returns the tcp connection (ports) exposed by a workload/pod peer
func GetPeerExposedTCPConnections(peer Peer) *common.ConnectionSet {
	switch currentPeer := peer.(type) {
	case *k8s.IPBlockPeer:
		return nil
	case *k8s.WorkloadPeer:
		// since virtual-machine specs does not contain Ports field(s); assuming it is exposed on all TCP conns
		if currentPeer.Kind() == parser.VirtualMachine {
			return common.GetAllTCPConnections()
		}
		return currentPeer.Pod.PodExposedTCPConnections()
	case *k8s.PodPeer:
		return currentPeer.Pod.PodExposedTCPConnections()
	default:
		return nil
	}
}

// isPeerExternal returns true if the input peer is an IPBlock or ingress-controller
func isPeerExternal(peer k8s.Peer) bool {
	if peer.PeerType() == k8s.IPBlockType {
		return true
	}
	if peer.GetPeerPod().Name == common.IngressPodName && peer.GetPeerNamespace().Name == common.IngressPodNamespace {
		return true
	}
	return false
}

// getPeerPrimaryNetwork returns the primary network (connected to eth0 interface) of the peer.
// note that: each peer may be connected to only one primary network on its primary interface eth0; it would be
// either the cluster's pod network or a primary UDN
func (pe *PolicyEngine) getPeerPrimaryNetwork(peer k8s.Peer) common.NetworkData {
	if isPeerExternal(peer) { // external peer may connect with all network interfaces in the cluster if xgress is enabled
		return common.NetworkData{} // the network data is not relevant for external peers
	}
	// peer is not external,
	// check if the peer belongs to a primary-network (udn/cudn)
	if networkData, ok := pe.primaryNetworks[peer.GetPeerNamespace().Name]; ok {
		return networkData
	}
	// if it does not belong to a primary network: return default network data (pod network)
	// if the pod is not in a primary network its default network is the pod network
	return common.DefaultNetworkData()
}

func (pe *PolicyEngine) getPeerSecondaryNetworks(peer k8s.Peer) map[string]common.NetworkData {
	if isPeerExternal(peer) {
		return nil
	}
	res := make(map[string]common.NetworkData)
	// go through the pod's secondaryNetworks, return networks that are inserted to the policy-engine
	// and that the namespace of the NAD matches the pod's namespace or pod's network namespace
	for networkName, networkInfo := range peer.GetPeerPod().SecondaryNetworks {
		peerNetworkNs := peer.GetPeerNamespace().Name
		if networkInfo.Namespace != "" {
			peerNetworkNs = networkInfo.Namespace
		}
		networkData, ok := pe.secondaryNetworks[networkName]
		if ok && networkData.Namespaces[peerNetworkNs] { // the pod must be in a namespace that has matching NAD
			res[networkName] = networkData.NetworkData
		}
	}
	return res
}

// findCommonSecondaryNetworkForPeersPair returns all secondary interfaces which both src and dst are connected to
func (pe *PolicyEngine) findCommonSecondaryNetworkForPeersPair(src, dst k8s.Peer) []common.NetworkData {
	res := []common.NetworkData{}
	srcSecondaryNets := pe.getPeerSecondaryNetworks(src)
	dstSecondaryNets := pe.getPeerSecondaryNetworks(dst)
	if srcSecondaryNets == nil || dstSecondaryNets == nil {
		return nil
	}
	// note that : network name is unique in the cluster;
	for netName, netData := range srcSecondaryNets {
		if _, ok := dstSecondaryNets[netName]; ok {
			res = append(res, netData)
		}
	}
	return res
}

// podsFromIsolatedPrimaryNetworks determines whether two Kubernetes peers (src and dst) are isolated from each other
// on their primary network, and returns the relevant network data for their connection.
//
// The logic considers various scenarios:
//   - If exposure analysis is enabled, always returns not isolated with empty network data
//     (exposure analysis is not supported with virtual interfaces and multiple networks).
//   - If either peer is external, returns not isolated with the other's primary network.
//   - If both peers are in primary networks:
//   - If both are UDNs in the same namespace, or both are CUDNs in the same network, they are not isolated.
//   - Otherwise, they are isolated.
//   - If only one peer is in a primary network, they are isolated, and the primary network is returned.
//   - Otherwise, they are not isolated and the default network is returned.
//   - In any other case (should not occur), returns isolated with empty network data.
//
//gocyclo:ignore
func (pe *PolicyEngine) podsFromIsolatedPrimaryNetworks(src, dst k8s.Peer) (primaryIsolated bool, primaryNetwork common.NetworkData) {
	if pe.exposureAnalysisFlag {
		return false, common.DefaultNetworkData()
	}
	srcPrimaryNetwork := pe.getPeerPrimaryNetwork(src) // the primary network: either pod-network or a primary udn/cudn
	dstPrimaryNetwork := pe.getPeerPrimaryNetwork(dst)
	switch {
	case isPeerExternal(src):
		return false, dstPrimaryNetwork
	case isPeerExternal(dst):
		return false, srcPrimaryNetwork
	case srcPrimaryNetwork.Interface == common.PodNetwork && dstPrimaryNetwork.Interface == common.PodNetwork:
		return false, srcPrimaryNetwork
	case srcPrimaryNetwork.Interface == common.Primary && dstPrimaryNetwork.Interface == common.Primary:
		if srcPrimaryNetwork.ResourceKind == common.UDN && dstPrimaryNetwork.ResourceKind == common.UDN &&
			src.GetPeerNamespace() == dst.GetPeerNamespace() {
			return false, srcPrimaryNetwork
		}
		if srcPrimaryNetwork.ResourceKind == common.CUDN && dstPrimaryNetwork.ResourceKind == common.CUDN &&
			srcPrimaryNetwork.NetworkName == dstPrimaryNetwork.NetworkName {
			return false, srcPrimaryNetwork
		}
		// Different primary networks , isolated peers
		return true, srcPrimaryNetwork

		// only one peer in a primary network; peers are isolated since the primary (c)udn isolates its peers
	case srcPrimaryNetwork.Interface == common.Primary && dstPrimaryNetwork.Interface != common.Primary,
		dstPrimaryNetwork.Interface == common.Primary && srcPrimaryNetwork.Interface != common.Primary:
		if srcPrimaryNetwork.Interface == common.Primary {
			return true, srcPrimaryNetwork
		}
		return true, dstPrimaryNetwork
	default: // should not get here
		return true, common.NetworkData{}
	}
}

// allAllowedConnections: returns allowed connection between input strings of src and dst in default network
// currently used only for testing on the default pod-network (computations based on all policy resources (e.g. ANP, NP & BANP))
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
	return allowedConns[0], err
}

// AllAllowedConnectionsBetweenWorkloadPeers returns the allowed connections from srcPeer to dstPeer per network,
// * expecting that srcPeer and dstPeer are in level of workloads (WorkloadPeer)
// * A pair of pods can establish multiple distinct communication paths between them by utilizing both:
// - their primary network interface (pod-network or a (C)UDN)
// - any shared secondary interfaces (NADs)
func (pe *PolicyEngine) AllAllowedConnectionsBetweenWorkloadPeers(srcPeer, dstPeer Peer) ([]*common.ConnectionSet, error) {
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
	return nil, errors.New(alerts.BothSrcAndDstIPsErrStr(srcPeer.String(), dstPeer.String()))
}

func (pe *PolicyEngine) getPeerUDNNamesAndKind(peer k8s.Peer) (peerUDNName, peerUDNKind string) {
	if isPeerExternal(peer) {
		return "", ""
	}
	if _, ok := pe.primaryNetworks[peer.GetPeerNamespace().Name]; ok {
		return pe.primaryNetworks[peer.GetPeerNamespace().Name].NetworkName,
			common.ResourceString(pe.primaryNetworks[peer.GetPeerNamespace().Name].ResourceKind)
	}
	return "", ""
}

// allAllowedConnectionsBetweenPeers: returns the list of allowed connections from srcPeer to dstPeer per network
// expecting that srcPeer and dstPeer are in level of pods (PodPeer)
// allowed conns are computed considering all the available resources of k8s network policy api:
// - admin-network-policies, network-policies and baseline-admin-network-policies
// - or multi-networkpolicy
func (pe *PolicyEngine) allAllowedConnectionsBetweenPeers(srcPeer, dstPeer Peer) ([]*common.ConnectionSet, error) {
	srcK8sPeer := srcPeer.(k8s.Peer)
	dstK8sPeer := dstPeer.(k8s.Peer)
	res := []*common.ConnectionSet{}
	// cases where any connection is always allowed
	if isPodToItself(srcK8sPeer, dstK8sPeer) || isPeerNodeIP(srcK8sPeer, dstK8sPeer) || isPeerNodeIP(dstK8sPeer, srcK8sPeer) {
		conn := common.MakeConnectionSet(true)
		conn.AddCommonImplyingRule("", common.PodToItselfRule, true)
		conn.AddCommonImplyingRule("", common.PodToItselfRule, false)
		return []*common.ConnectionSet{conn}, nil // this case is ignored for final output
	}
	networks := []common.NetworkData{} // to store the shared primary and secondary networks of src and dst peers

	// Primary Network
	// check if there is a primary network (podNetwork or (c)udn) which connect the pods on eth0 interface (the primary interface).
	// pods belonging to different primary networks/ UDNs are inherently isolated on their primary networks.
	primaryIsolated, primaryNetwork := pe.podsFromIsolatedPrimaryNetworks(srcK8sPeer, dstK8sPeer)
	// if pods are primary-isolated, this means at least one of them is isolated by a different user-defined network,
	// there is no connection between the pods on a primary network
	if primaryIsolated {
		primaryConn := common.MakeConnectionSet(false)
		srcUDN, srcUDNKind := pe.getPeerUDNNamesAndKind(srcK8sPeer)
		dstUDN, dstUDNKind := pe.getPeerUDNNamesAndKind(dstK8sPeer)
		primaryConn.AddCommonImplyingRule(common.UDNRuleKind, common.IsolatedUDNRule(k8s.ConstPeerString(srcK8sPeer),
			k8s.ConstPeerString(dstK8sPeer), srcUDN, dstUDN, srcUDNKind, dstUDNKind), true)
		primaryConn.AddCommonImplyingRule(common.UDNRuleKind, common.IsolatedUDNRule(k8s.ConstPeerString(srcK8sPeer),
			k8s.ConstPeerString(dstK8sPeer), srcUDN, dstUDN, srcUDNKind, dstUDNKind), false)
		primaryConn.NetworkData = primaryNetwork
		res = append(res, primaryConn) // append it and proceed to check if there are secondary interfaces
	} else { // not primary isolated: append to shared networks in order to compute the allowed conns on it
		networks = append(networks, primaryNetwork)
	}

	// Secondary Networks:
	// Note that:
	// Despite primary-network isolation, pods in different UDNs can establish communication through secondary network interfaces.
	// These interfaces are provisioned using Multus-CNI and NADs allowing pods to connect to a common shared secondary networks.
	if !pe.exposureAnalysisFlag { // exposure is not supported with multiple networks
		networks = append(networks, pe.findCommonSecondaryNetworkForPeersPair(srcK8sPeer, dstK8sPeer)...)
	}

	// get all allowed conns between src and dst per each shared network
	// note that: networks may contain at most one primary network (pod-network/udn)
	// and may contain 0, 1 or multiple secondary networks
	for _, network := range networks {
		// for each network:
		// egress: get egress allowed connections between the src and dst by
		// walking through all relevant egress policies capturing the src;
		// primary network: evaluating first ANPs then NPs and finally the BANP
		// secondary network : evaluating multi-NP
		conn, err := pe.allAllowedXgressConnections(srcK8sPeer, dstK8sPeer, false, network)
		if err != nil {
			return nil, err
		}
		conn.SetExplResult(false)
		if conn.IsEmpty() && !pe.explain {
			conn.NetworkData = network
			res = append(res, conn)
			continue
		}
		// ingress: get ingress allowed connections between the src and dst in current network by
		// walking through all relevant k8s ingress policies capturing the dst;
		// primary network: evaluating first ANPs then NPs and finally the BANP
		// secondary network : evaluating multi-NP
		ingressRes, err := pe.allAllowedXgressConnections(srcK8sPeer, dstK8sPeer, true, network)
		if err != nil {
			return nil, err
		}
		ingressRes.SetExplResult(true)
		conn.Intersection(ingressRes)
		conn.NetworkData = network
		res = append(res, conn)
	}
	return res, nil
}

// allAllowedXgressConnections returns the allowed connections from srcPeer to dstPeer on the
// given direction (ingress/egress)
// * if src and dst are in a secondary network (referenced by a NAD) : returns allowed conns by analyzing relevant multiNetworkPolicies
// * otherwise (peers are in a (C)UDN or pod-network) : returns the allowed conns by analyzing k8s api policies (e.g NetworkPolicy /
// (Baseline)AdminNetworkPolicy)
func (pe *PolicyEngine) allAllowedXgressConnections(src, dst k8s.Peer, isIngress bool,
	network common.NetworkData) (allowedConns *common.ConnectionSet, err error) {
	if network.Interface == common.Secondary && network.ResourceKind == common.NAD {
		return pe.allAllowedXgressConnectionsByMultiNetpolsCRDs(src, dst, isIngress, network.NetworkName)
	}
	// on a primary network: (udn/cudn) or pod-network
	return pe.allAllowedXgressConnectionsByk8sNetpols(src, dst, isIngress)
}

// policiesLayerXgressConns stores data of connections from policies of same type (layer) on ingress/egress direction.
// this is used to store:
// - the connections between two peers on ingress/ egress or
// - in case of exposure-analysis: the connections from a peer to entire-cluster (on egress) or from entire-cluster to a peer (on ingress)
type policiesLayerXgressConns struct {
	// isCaptured : indicates if the xgress connections are captured by the policies in the current layer
	isCaptured bool
	// layerConns : the xgress connections between the peers / (peer and entire-cluster) from all relevant policies in the current layer
	layerConns *k8s.PolicyConnections
}

// initEmptyPoliciesLayerXgressConns returns a new empty policiesLayerXgressConns object
func initEmptyPoliciesLayerXgressConns() *policiesLayerXgressConns {
	return &policiesLayerXgressConns{isCaptured: false, layerConns: k8s.NewPolicyConnections()}
}

// allAllowedXgressConnectionsByk8sNetpols: returns the allowed connections from srcPeer to dstPeer on the
// given direction (ingress/egress) by analyzing k8s network policy api objects
// allowed conns are computed by walking through all the available resources of k8s network policy api:
// admin-network-policies, network-policies and baseline-admin-network-policies;
// considering the precedence of each policy
// in case of exposure-analysis it also checks and updates if a src is exposed to entire cluster on egress
// or dst is exposed to entire cluster on ingress
// this is relevant for primary and default pod network
func (pe *PolicyEngine) allAllowedXgressConnectionsByk8sNetpols(src, dst k8s.Peer, isIngress bool) (allowedConns *common.ConnectionSet,
	err error) {
	// Tanya TODO: think about the implicitly denied protocols/port ranges
	// (due to NPs capturing this src/dst, but defining only some of protocols/ports)
	// How to update implying rules in this case?

	// first get allowed xgress conn between the src and dst from the ANPs
	// (in case of exposure-analysis get also cluster wide conns of the selected peer from the ANPs)
	// note that:
	// - anpConns.layerConns (or anpExposure.layerConns) may contain allowed, denied or/and passed connections;
	// connections consider rules and policies precedence
	// - anpConns.isCaptured is true iff there is at least one rule in the input ANPs that captures both src and dst;
	// because anp rules are read as is and don't contain any implicit isolation effects for the Pods selected by the AdminNetworkPolicy.
	// anpExposure - is relevant only if pe.exposureAnalysisFlag == true
	// - anpExposure.isCaptured is true iff there is at least one ANP that exposes the relevant peer (src on egress/ dst on ingress)
	// to entire-cluster
	anpConns, anpExposure, err := pe.getAllAllowedXgressConnectionsFromANPs(src, dst, isIngress)
	if err != nil {
		return nil, err
	}
	// optimizations
	// if all connections between src and dst were determined by the AdminNetworkPolicies (ANP layer); we actually can return the result.
	// but if the exposure-analysis flag is on, and we are also computing the exposure to entire-cluster of the
	// selected pod (src if egress/ dst if ingress), then before returning we need to check if also the connection with entire-cluster
	// was determined by the ANP layer or should proceed to get the exposure connections from the lower layers.
	// example:
	// assume ANP denies all conns from a -> b (ANP determined all conns to b; if exposure analysis is off no need to continue to NP/BANP)
	// But:
	// assume NP exposes A to entire-cluster on all-conns (if we don't continue - this would not be computed and will have wrong
	// results as exposure to entire-cluster is computed once for each direction)

	podExposureUpdatedFlag := false    // indicates if all connections of exposure to entire cluster were determined by the ANP layer
	anpConnsDeterminedAllFlag := false // indicates if all connections between src and dst were determined by the ANP layer
	// if all cluster-wide conns were determined by the ANP then update the selected peer's cluster wide exposure
	if pe.exposureAnalysisFlag && anpExposure.layerConns.DeterminesAllConns() {
		podExposureUpdatedFlag = true // the ANP determined all connections between the selected peer and entire-cluster, so we can update
		// the entire cluster exposure data of the pod
		// and there is no need to wait and consider the exposure to entire-cluster conns of lower layers (NP and BANP)
		updatePeerXgressClusterWideExposure(anpExposure.layerConns.AllowedConns, src, dst, isIngress)
	}
	// if all the conns between src and dst were determined by the ANPs : return the allowed conns
	if anpConns.layerConns.DeterminesAllConns() {
		// the ANP layer determined all connections between src and dst, then no need to consider what connections are allowed between src and dst
		// from lower layers (NP/ BANP).
		if !pe.exposureAnalysisFlag || podExposureUpdatedFlag {
			// if exposure analysis is off or all exposure conns to entire-cluster were also determined by the ANP layer
			// then return the allowed conns between src and dst (no need to proceed to other layers)
			// since NPs/BANPs are not relevant here, perform the subtract below
			anpConns.layerConns.AllowedConns.Subtract(anpConns.layerConns.DeniedConns) // update explainabiliy data
			return anpConns.layerConns.AllowedConns, nil
		}
		// else : exposure-analysis is on and still not determined continue in order to compute and update the exposure to
		// entire-cluster of the selected pod
		anpConnsDeterminedAllFlag = true
	}

	// second get the allowed xgress conns between the src and dst from the netpols
	// (in case of exposure-analysis get also cluster wide conns of the selected peer from the netpols)
	// note that :
	// - npConns.layerConns (or npExposure.layerConns) contains only allowed connections
	// - npConns.isCaptured is true iff there are policies selecting either src or dst based on the checked direction (ingress/ egress)
	// - npExposure is relevant only if pe.exposureAnalysisFlag == true
	// - npExposure.isCaptured is true iff there is at least one policy that exposes the relevant peer (src on egress/ dst on ingress)
	// to entire-cluster
	npConns, npExposure, err := pe.getAllAllowedXgressConnsFromNetpols(src, dst, isIngress)
	if err != nil {
		return nil, err
	}

	// get default xgress connection between src and dst from the BANP/ system-default;
	// (in case of exposure-analysis get also cluster wide conns of the selected peer from the BANP/ system-default)
	// note that :
	// - if there is no banp in the input resources, then defaultConns.layerConns (or defaultExposure.layerConns)
	// is system-default which is allow-all
	// - if the banp captures the xgress connection; then defaultConns (or defaultExposure.layerConns) may contain allowed and denied conns
	// - defaultExposure is relevant only if pe.exposureAnalysisFlag == true
	defaultConns, defaultExposure, err := pe.getXgressDefaultConns(src, dst, isIngress)
	if err != nil {
		return nil, err
	}
	// after having allowed xgress conns from all policies layers separately, compute final all allowed xgress conns
	// considering layers precedences:

	// in case of exposure-analysis: update cluster wide exposure data for relevant pod (src on egress, dst on ingress)
	if pe.exposureAnalysisFlag && !podExposureUpdatedFlag {
		clusterWideExposureFromAllLayers := allAllowedXgressConnsConsideringAllLayersConns(anpExposure, npExposure, defaultExposure)
		updatePeerXgressClusterWideExposure(clusterWideExposureFromAllLayers, src, dst, isIngress)
	}
	if anpConnsDeterminedAllFlag { // if all conns between the src and dst were determined by ANP layer, return the allowed
		// conns from the ANP layer
		// since NPs/BANPs are not relevant here, perform the subtract below
		anpConns.layerConns.AllowedConns.Subtract(anpConns.layerConns.DeniedConns) // update explainabiliy data
		return anpConns.layerConns.AllowedConns, nil
	}
	// return all allowed xgress connections between the src and dst (final result computed considering all layers conns)
	return allAllowedXgressConnsConsideringAllLayersConns(anpConns, npConns, defaultConns), nil
}

// allAllowedXgressConnsConsideringAllLayersConns gets connections from all policies layers and compute the allowed connections on
// the given direction considering on which policies-layer the xgress connection was captured and the precedence of each policies layer
func allAllowedXgressConnsConsideringAllLayersConns(anpConns, npConns,
	defaultOrBanpConns *policiesLayerXgressConns) (allowedConns *common.ConnectionSet) {
	switch {
	case npConns.isCaptured && !anpConns.isCaptured:
		// ANPs don't capture the connection; NPs capture the peers, return allowed conns from netpols
		return npConns.layerConns.AllowedConns
	case npConns.isCaptured && anpConns.isCaptured:
		// if conns between src and dst (or between peer and entire-cluster) were captured by both the admin-network-policies and
		// by network-policies
		// collect conns:
		// - traffic that was allowed or denied by ANPs will not be affected by the netpol conns.
		// - traffic that has no match in ANPs but allowed by NPs is added to allowed conns.
		// - pass conns from ANPs, are determined by NPs conns;
		// note that allowed conns by netpols, imply deny on other traffic;
		// so ANPs.pass conns which intersect with NPs.allowed are added to allowed conns result;
		// other pass conns (which don't intersect with NPs allowed conns) are not allowed implicitly.
		anpConns.layerConns.CollectAllowedConnsFromNetpols(npConns.layerConns)
		return anpConns.layerConns.AllowedConns
	default: // !npCaptured - netpols don't capture the connections between src and dst - delegate to banp
		// possible cases :
		// 1. ANPs capture the connection, netpols don't, return the allowed conns from ANPs considering default conns (& BANP)
		// 2. only BANP captures conns between the src and dst (there are no policies in the higher layers)
		// 3. only default conns (no ANPs, nor BANP)
		// then collect conns from banp (or system-default):
		// this also determines what happens on traffic (ports) which are not mentioned in the (B)ANPs;
		// since (B)ANP rules are read as is only.
		anpConns.layerConns.CollectConnsFromBANP(defaultOrBanpConns.layerConns)
		return anpConns.layerConns.AllowedConns
	}
}

// updatePeerXgressClusterWideExposure updates the cluster-wide exposure of the pod which is selected by input policies.
// used only when exposure-analysis is active
func updatePeerXgressClusterWideExposure(allowedXgressExposureConns *common.ConnectionSet, src, dst k8s.Peer, isIngress bool) {
	if isIngress && dst.PeerType() != k8s.IPBlockType && !dst.GetPeerPod().FakePod {
		// policy selecting dst (dst pod is real)
		// update its ingress entire cluster connection relying on policies data
		dst.GetPeerPod().UpdatePodXgressExposureToEntireClusterData(allowedXgressExposureConns, isIngress)
	} else if !isIngress && src.PeerType() != k8s.IPBlockType && !src.GetPeerPod().FakePod {
		// policy selecting src
		// update its egress entire cluster connection relying on policies data
		src.GetPeerPod().UpdatePodXgressExposureToEntireClusterData(allowedXgressExposureConns, isIngress)
	}
}

// analyzing network-policies for conns between peers (object kind == NetworkPolicy):

// getAllAllowedXgressConnsFromNetpols checks and returns the set of allowed connections from src to dst on the given
// direction(ingress/egress), by network policies rules, if those connections from src to dst are captured by network policies.
// also, in case of exposure-analysis, checks and returns cluster wide exposure connections if a src is exposed
// to all namespaces on egress or dst is exposed to all namespaces cluster on ingress.
// note that network-policies connections represent only allowed conns.
// note that: if there are policies selecting src (on egress) or dst (on ingress), then the xgress connection is captured;
// since NetworkPolicy rules implicitly deny unmentioned connections.
func (pe *PolicyEngine) getAllAllowedXgressConnsFromNetpols(src, dst k8s.Peer,
	isIngress bool) (policiesConns, exposureConns *policiesLayerXgressConns, err error) {
	policiesConns = initEmptyPoliciesLayerXgressConns() // result of allowed conns between the src and dst
	exposureConns = initEmptyPoliciesLayerXgressConns() // result of cluster wide exposure of selected pod
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
		return nil, nil, err
	}

	if len(netpols) == 0 {
		// if the given direction is not capturing the connection between src and dst,
		// this will be ignored and skipped so allowed conns will be determined later by BANP, or default (allow-all)
		return policiesConns, exposureConns, nil
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
			return nil, nil, err
		}
		if pe.exposureAnalysisFlag {
			// if there is at least one netpol capturing the peer, then allowedConns is captured
			// (either allowed by rule or implicitly denied because of the rule's absence)
			exposureConns.isCaptured = true
			// update the cluster wide exposure result from the relevant netpol's data
			if isIngress && !policy.IngressPolicyClusterWideExposure.IsEmpty() {
				exposureConns.layerConns.AllowedConns.Union(policy.IngressPolicyClusterWideExposure.AllowedConns, false)
			} else if !isIngress && !policy.EgressPolicyClusterWideExposure.IsEmpty() {
				exposureConns.layerConns.AllowedConns.Union(policy.EgressPolicyClusterWideExposure.AllowedConns, false)
			}
		}
		allowedConns.Union(policyAllowedConnectionsPerDirection, true) // collect implying rules from multiple NPs
	}
	// putting the result in policiesConns object to be compared with conns allowed by ANP/BANP later
	policiesConns.isCaptured = true
	policiesConns.layerConns.AllowedConns = allowedConns
	return policiesConns, exposureConns, nil
}

// determineAllowedConnsPerDirection returns the policy's allowed connections between the
// peers in the given direction
func (pe *PolicyEngine) determineAllowedConnsPerDirection(policy *k8s.NetworkPolicy, src, dst k8s.Peer,
	isIngress bool) (*common.ConnectionSet, error) {
	if isIngress {
		// get ingress allowed conns between src and dst
		switch {
		case policy.IngressPolicyClusterWideExposure.AllowedConns.AllowAll && src.PeerType() == k8s.PodType:
			return policy.IngressPolicyClusterWideExposure.AllowedConns, nil
		default:
			return policy.GetXgressAllowedConns(src, dst, true)
		}
	}
	// else get egress allowed conns between src and dst
	switch {
	case policy.EgressPolicyClusterWideExposure.AllowedConns.AllowAll && dst.PeerType() == k8s.PodType:
		return policy.EgressPolicyClusterWideExposure.AllowedConns, nil
	default:
		return policy.GetXgressAllowedConns(src, dst, false)
	}
}

// analyzing admin-network-policies for conns between peers (object kind == AdminNetworkPolicy):

// getAllAllowedXgressConnectionsFromANPs checks and returns the connections data from src to dst on given direction (ingress/egress)
// by analyzing admin network policies rules;
// in case of exposure-analysis returns also connections data between src and entire-cluster on egress / entire-cluster and dst on ingress.
// note that:
// - ANP connections may be allowed, passed and denied
// - a connection between src and dst is captured by an ANP iff there is an xgress rule capturing both peers, since
// AdminNetworkPolicy rules should be read as-is, i.e. there will not be any implicit isolation effects for
// the Pods selected by the AdminNetworkPolicy, as opposed to implicit deny NetworkPolicy rules imply.
func (pe *PolicyEngine) getAllAllowedXgressConnectionsFromANPs(src, dst k8s.Peer,
	isIngress bool) (policiesConns, exposureConns *policiesLayerXgressConns, err error) {
	policiesConns = initEmptyPoliciesLayerXgressConns() // result of allowed conns between the src and dst
	exposureConns = initEmptyPoliciesLayerXgressConns() // result of cluster wide exposure of selected pod
	// iterate the sorted admin network policies in order to compute the allowed, pass, and denied xgress connections between the peers
	// from the admin netpols capturing the src (if !isIngress)/ capturing the dst (if isIngress true).
	// connections are computed considering ANPs priorities (rules of an ANP with lower priority take precedence on other ANPs rules)
	// and rules ordering in single ANP (coming first takes precedence).
	// if exposure-analysis is on, update cluster wide exposure result from the admin-policy's data
	for _, anp := range pe.sortedAdminNetpols {
		singleANPConns := k8s.NewPolicyConnections()
		// collect the allowed, pass, and denied connectivity from the relevant rules into policiesConns
		if !isIngress { // egress
			selectsSrc, err := anp.Selects(src, false)
			if err != nil {
				return nil, nil, err
			}
			// if the anp captures the src, get the relevant egress conns between src and dst
			if selectsSrc {
				singleANPConns, err = anp.GetEgressPolicyConns(dst)
				if err != nil {
					return nil, nil, err
				}
				// if exposure-analysis is on, update also the exposure of the src to all namespaces on egress
				// if it is captured by current policy
				if pe.exposureAnalysisFlag {
					src.GetPeerPod().UpdatePodXgressProtectedFlag(false) // mark the pod is protected
					updateClusterWideExposureResultFromANP(exposureConns, anp.EgressPolicyClusterWideExposure)
				}
			}
		} else { // ingress
			selectsDst, err := anp.Selects(dst, true)
			if err != nil {
				return nil, nil, err
			}
			// if the anp captures the dst, get the relevant ingress conns (from src to dst)
			if selectsDst {
				singleANPConns, err = anp.GetIngressPolicyConns(src, dst)
				if err != nil {
					return nil, nil, err
				}
				// if exposure-analysis is on, update also the exposure of the dst from all namespaces on ingress
				// if it is captured by current policy
				if pe.exposureAnalysisFlag {
					dst.GetPeerPod().UpdatePodXgressProtectedFlag(true)
					updateClusterWideExposureResultFromANP(exposureConns, anp.IngressPolicyClusterWideExposure)
				}
			}
		}
		if !singleANPConns.IsEmpty() { // the anp is relevant (the xgress connection is captured)
			policiesConns.layerConns.CollectANPConns(singleANPConns)
		}
	}

	if policiesConns.layerConns.IsEmpty() {
		// conns between src and dst were not captured by the adminNetpols, to be determined by netpols/default conns
		policiesConns.isCaptured = false
	} else {
		policiesConns.isCaptured = true
	}
	policiesConns.layerConns.ComplementPassConns()
	exposureConns.layerConns.ComplementPassConns()
	return policiesConns, exposureConns, nil
}

// updateClusterWideExposureResultFromANP updates the cluster-wide exposure result of a pod from given (B)ANP exposure info
func updateClusterWideExposureResultFromANP(exposureResult *policiesLayerXgressConns,
	xgressPolicyClusterWideExposure *k8s.PolicyConnections) {
	if !xgressPolicyClusterWideExposure.IsEmpty() {
		exposureResult.isCaptured = true
		exposureResult.layerConns.CollectANPConns(xgressPolicyClusterWideExposure)
	}
}

// analyzing baseline-admin-network-policy for conns between peers (object kind == BaselineAdminNetworkPolicy):

// getXgressDefaultConns returns the default connections between src and dst on the given direction (ingress/egress);
// considering the existence of a baseline-admin-network-policy
// if there is a BANP in the input resources, it is analyzed; if it captures xgress conns between src and dst,
// then the captured conns are returned.
// if there is no BANP in the policy-engine, then default allow-all connections is returned.
// in case of exposure-analysis: returns default connections also between src and entire-cluster
// on egress / dst and entire-cluster on ingress.
// - note that the results may contain allowed / denied connections.
func (pe *PolicyEngine) getXgressDefaultConns(src, dst k8s.Peer, isIngress bool) (defaultConns,
	exposureConns *policiesLayerXgressConns, err error) {
	// the "layerConns" field of defaultConns and exposureConns is updated with system-default conns also
	// if banp does not exist/ does not capture the peers.
	defaultConns = initEmptyPoliciesLayerXgressConns()  // result of allowed conns between the src and dst
	exposureConns = initEmptyPoliciesLayerXgressConns() // result of cluster wide exposure of selected pod
	banpConns := k8s.NewPolicyConnections()
	if pe.baselineAdminNetpol != nil {
		if isIngress { // ingress
			selectsDst, err := pe.baselineAdminNetpol.Selects(dst, true)
			if err != nil {
				return nil, nil, err
			}
			// if the banp selects the dst on ingress, get ingress conns
			if selectsDst {
				banpConns, err = pe.baselineAdminNetpol.GetIngressPolicyConns(src, dst)
				if err != nil {
					return nil, nil, err
				}
				if pe.exposureAnalysisFlag {
					// if exposure-analysis is on, update also the exposure of the dst from all namespaces on ingress
					// if it is captured by current policy
					dst.GetPeerPod().UpdatePodXgressProtectedFlag(true)
					updateClusterWideExposureResultFromANP(exposureConns, pe.baselineAdminNetpol.IngressPolicyClusterWideExposure)
				}
			}
		} else { // egress (!isIngress)
			selectsSrc, err := pe.baselineAdminNetpol.Selects(src, false)
			if err != nil {
				return nil, nil, err
			}
			// if the banp selects the src on egress, get egress conns
			if selectsSrc {
				banpConns, err = pe.baselineAdminNetpol.GetEgressPolicyConns(dst)
				if err != nil {
					return nil, nil, err
				}
				// if exposure-analysis is on, update also the exposure of the src to all namespaces on egress
				// if it is captured by current policy
				if pe.exposureAnalysisFlag {
					src.GetPeerPod().UpdatePodXgressProtectedFlag(false)
					updateClusterWideExposureResultFromANP(exposureConns, pe.baselineAdminNetpol.EgressPolicyClusterWideExposure)
				}
			}
		}
	}

	defaultConns.layerConns = banpConns
	exposureConns.layerConns.AllowedConns = common.MakeConnectionSet(true)
	// if no banp or banp rules didn't capture xgress conn between src and dst, return system-default: allow-all;
	// if banp rule captured xgress conn, only DeniedConns should be impacted by banp rule,
	// whenever AllowedConns should anyway be system-default: allow-all (or assumed allow-all for IP-blocks)
	if (isIngress && dst.PeerType() == k8s.IPBlockType) || (!isIngress && src.PeerType() == k8s.IPBlockType) {
		defaultConns.layerConns.AllowedConns = common.MakeConnectionSetWithRule(true, "", common.IPDefaultRule, isIngress)
	} else {
		defaultConns.layerConns.AllowedConns = common.MakeConnectionSetWithRule(true, "", common.SystemDefaultRule, isIngress)
	}
	return defaultConns, exposureConns, nil
}

// allAllowedXgressConnectionsByMultiNetpolsCRDs returns allowed egress/ingress conns between the src and dst in a secondary network by
// analyzing the multi-network-policies
func (pe *PolicyEngine) allAllowedXgressConnectionsByMultiNetpolsCRDs(src, dst k8s.Peer, isIngress bool,
	networkName string) (*common.ConnectionSet, error) {
	// Note that: currently secondary networks describe connections between workloads in the cluster-only (both src and dst are PodPeer)
	// conns between external-ipblock-peers and internal-pods are attached to a primary network or
	//  the pod-network (depending on the primary network that the internal peer belongs to)

	// @todo: selecting internal peers by their IP-addresses with an IPBlock selector in a policy's rule is not supported yet

	// relevant multi-network-policies: policies that are in the given network and capture dst if isIngress, else capture src
	var err error
	var multiNetpols []*k8s.MultiNetworkPolicy
	if isIngress {
		multiNetpols, err = pe.getMultiNetworkPoliciesSelectingPod(dst.GetPeerPod(), netv1.PolicyTypeIngress, networkName)
	} else {
		multiNetpols, err = pe.getMultiNetworkPoliciesSelectingPod(src.GetPeerPod(), netv1.PolicyTypeEgress, networkName)
	}
	if err != nil {
		return nil, err
	}

	if len(multiNetpols) == 0 {
		return common.MakeConnectionSet(true), nil // all connections allowed - no relevant multi-network-policy captures the relevant pod
		// on the required direction
	}

	allowedConns := common.MakeConnectionSet(false)

	// iterate relevant multi-network-policies
	for _, mnp := range multiNetpols {
		// determine policy's allowed connections between the peers for the direction
		// if isIngress: check for ingress rules that capture src within 'from'
		// if not isIngress: check for egress rules that capture dst within 'to'
		// collect the allowed connectivity from the relevant rules into allowedConns
		var policyAllowedConnectionsPerDirection *common.ConnectionSet
		var err error
		if isIngress {
			policyAllowedConnectionsPerDirection, err = mnp.GetMNPXgressAllowedConns(src, dst, true, networkName)
		} else {
			policyAllowedConnectionsPerDirection, err = mnp.GetMNPXgressAllowedConns(src, dst, false, networkName)
		}
		if err != nil {
			return allowedConns, err
		}
		allowedConns.Union(policyAllowedConnectionsPerDirection, true)
	}
	return allowedConns, nil
}

func (pe *PolicyEngine) getMultiNetworkPoliciesSelectingPod(pod *k8s.Pod, direction netv1.PolicyType,
	networkName string) ([]*k8s.MultiNetworkPolicy, error) {
	multiNetpols := pe.multiNetpolsMap[pod.Namespace] // policies must be in same namespace as the pod
	res := []*k8s.MultiNetworkPolicy{}
	for _, mnp := range multiNetpols {
		// check if the annotation policy-for targets the given network; and its namespace is in the network's namespaces
		targetsNetwork, err := mnp.TargetsNetwork(networkName, pe.secondaryNetworks[networkName].Namespaces)
		if err != nil {
			return nil, err
		}
		if !targetsNetwork {
			continue
		}
		// check if the policy selects the given pod and affects given direction
		selects, err := mnp.Selects(pod, string(direction))
		if err != nil {
			return nil, err
		}
		if selects {
			res = append(res, mnp)
		}
	}
	return res, nil
}
