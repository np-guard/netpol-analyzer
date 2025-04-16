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
		return currentPeer.Pod.PodExposedTCPConnections()
	case *k8s.PodPeer:
		return currentPeer.Pod.PodExposedTCPConnections()
	default:
		return nil
	}
}

// podsFromIsolatedNetworks returns true if at least one pod belongs to an isolated user-defined-network
func podsFromIsolatedNetworks(src, dst k8s.Peer) bool {
	// if any of the peers is an external IP return false
	if src.PeerType() == k8s.IPBlockType || dst.PeerType() == k8s.IPBlockType {
		return false
	}
	// @todo : return false if one of the pods is ingress-controller (external)
	// return false if one pod is representative-peer
	// @todo: support exposure with UDNs - a pod in a udn should not be exposed to other primary UDNs
	if src.GetPeerNamespace() == nil || dst.GetPeerNamespace() == nil {
		return false
	}
	// if pods are in default pod networks (namespaces without UDN) - return false
	if src.GetPeerNamespace().PrimaryUDN == nil && dst.GetPeerNamespace().PrimaryUDN == nil {
		return false
	}
	// if pods are in same user-defined network
	if src.GetPeerNamespace().PrimaryUDN == dst.GetPeerNamespace().PrimaryUDN {
		return false
	}
	// at least one pod is in an isolated UDN
	return true
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
	return nil, errors.New(alerts.BothSrcAndDstIPsErrStr(srcPeer.String(), dstPeer.String()))
}

func getUDNsNames(src, dst k8s.Peer) (srcUDN, dstUDN string) {
	if src.GetPeerNamespace().PrimaryUDN != nil {
		srcUDN = src.GetPeerNamespace().Name
	}
	if dst.GetPeerNamespace().PrimaryUDN != nil {
		dstUDN = dst.GetPeerNamespace().Name
	}
	return srcUDN, dstUDN
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
		res = common.MakeConnectionSet(true)
		res.AddCommonImplyingRule("", common.PodToItselfRule, true)
		res.AddCommonImplyingRule("", common.PodToItselfRule, false)
		return res, nil
	}
	// if pods are from different user-defined networks, return empty result (no conns)
	if podsFromIsolatedNetworks(srcK8sPeer, dstK8sPeer) {
		res = common.MakeConnectionSet(false)
		srcUDN, dstUDN := getUDNsNames(srcK8sPeer, dstK8sPeer)
		res.AddCommonImplyingRule(common.UDNRuleKind, common.IsolatedUDNRule(k8s.ConstPeerString(srcK8sPeer, srcUDN != ""),
			k8s.ConstPeerString(dstK8sPeer, dstUDN != ""), srcUDN, dstUDN), true)
		res.AddCommonImplyingRule(common.UDNRuleKind, common.IsolatedUDNRule(k8s.ConstPeerString(srcK8sPeer, srcUDN != ""),
			k8s.ConstPeerString(dstK8sPeer, dstUDN != ""), srcUDN, dstUDN), false)
		return res, nil
	}
	// egress: get egress allowed connections between the src and dst by
	// walking through all k8s egress policies capturing the src;
	// evaluating first ANPs then NPs and finally the BANP
	res, err = pe.allAllowedXgressConnections(srcK8sPeer, dstK8sPeer, false)
	if err != nil {
		return nil, err
	}
	res.SetExplResult(false)
	if res.IsEmpty() && !pe.explain {
		return res, nil
	}
	// ingress: get ingress allowed connections between the src and dst by
	// walking through all k8s ingress policies capturing the dst;
	// evaluating first ANPs then NPs and finally the BANP
	ingressRes, err := pe.allAllowedXgressConnections(srcK8sPeer, dstK8sPeer, true)
	if err != nil {
		return nil, err
	}
	ingressRes.SetExplResult(true)
	res.Intersection(ingressRes)
	return res, nil
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

// allAllowedXgressConnections: returns the allowed connections from srcPeer to dstPeer on the
// given direction (ingress/egress)
// allowed conns are computed by walking through all the available resources of k8s network policy api:
// admin-network-policies, network-policies and baseline-admin-network-policies;
// considering the precedence of each policy
// in case of exposure-analysis it also checks and updates if a src is exposed to entire cluster on egress
// or dst is exposed to entire cluster on ingress
func (pe *PolicyEngine) allAllowedXgressConnections(src, dst k8s.Peer, isIngress bool) (allowedConns *common.ConnectionSet, err error) {
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
