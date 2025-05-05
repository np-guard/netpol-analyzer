/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connlist

import (
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
	dotformatting "github.com/np-guard/netpol-analyzer/pkg/netpol/internal/formatting"
)

const (
	ipColor                  = "red2"
	nonIPPeerColor           = "blue"
	representativeObjColor   = "red2"
	entireClusterShape       = " shape=diamond"
	peerLineClosing          = "]"
	allPeersLbl              = "all pods"
	allNamespacesLbl         = "all namespaces"
	edgeWeightLabel          = " weight="
	ingWeight                = "1"
	egWeight                 = "0.5"
	ingressExposureEdgeColor = "darkorange2"
	egressExposureEdgeColor  = "darkorange4"
	connlistEdgeColor        = "gold2"
	exposureEdgeStyle        = " style=dashed"
	edgeFontColor            = "darkgreen"
)

var peerLineFormatPrefix = fmt.Sprintf("\t%%q [label=%%q color=%%q fontcolor=%%q")

// formatDOT: implements the connsFormatter interface for dot output format
type formatDOT struct {
	peersList []Peer // internally used peersList; in case of focusWorkload option contains only relevant peers
}

// peerNameAndColorByType returns the peer label and color to be represented in the graph, and whether the peer is
// external to cluster's namespaces
func peerNameAndColorByType(peer Peer) (nameLabel, color string, isExternal, isInUDN bool) {
	if peer.IsPeerIPType() {
		return peer.String(), ipColor, true, false
	} else if peer.Name() == common.IngressPodName {
		return peer.String(), nonIPPeerColor, true, false
	}
	return dotformatting.NodeClusterPeerLabel(peer.Name(), peer.Kind()), nonIPPeerColor, false,
		strings.Contains(peer.String(), common.UDNLabel)
}

// getPeerLine formats a peer line for dot graph
func getPeerLine(peer Peer) (peerLine string, isExternal, isInUDN bool) {
	peerNameLabel, peerColor, isExternalPeer, peerInUDN := peerNameAndColorByType(peer)
	return fmt.Sprintf(peerLineFormatPrefix+peerLineClosing, peer.String(), peerNameLabel, peerColor, peerColor), isExternalPeer, peerInUDN
}

// returns a dot string form of connections from list of Peer2PeerConnection objects
// and from exposure-analysis results if exists
// explain input is ignored since not supported with this format
func (d *formatDOT) writeOutput(conns []Peer2PeerConnection, exposureConns []ExposedPeer, exposureFlag, explain bool,
	focusConnStr string) (string, error) {
	// 1. declaration of maps and slices to be used for forming the graph lines
	nsPeers := make(map[string][]string) // map from regular namespace to its peers
	//  (grouping peers by namespaces which are not representative, neither udn-assigned)
	nsRepPeers := make(map[string][]string)  // map from representative namespace to its representative peers
	udnNsPeers := make(map[string][]string)  // map from udn-namespace to its peers
	externalPeersLines := make([]string, 0)  // list of peers which are not in a cluster's namespace (will not be grouped)
	edgeLines := make([]string, 0)           // list of edges lines (connections of connlist + exposure)
	peersVisited := make(map[string]bool, 0) // acts as a set
	// 2. add connlist results to the graph lines
	connsEdges, connsExternalPeers := d.addConnlistOutputData(conns, nsPeers, udnNsPeers, peersVisited)
	edgeLines = append(edgeLines, connsEdges...)
	externalPeersLines = append(externalPeersLines, connsExternalPeers...)
	// 3. add exposure-analysis results to the graph lines
	// @todo : add udnNsPeers when supporting exposure-analysis with UDN
	entireClusterLine, exposureEdges := addExposureOutputData(exposureConns, peersVisited, nsPeers, nsRepPeers)
	externalPeersLines = append(externalPeersLines, entireClusterLine...)
	edgeLines = append(edgeLines, exposureEdges...)
	// 4. sort graph lines
	sort.Strings(edgeLines)
	sort.Strings(externalPeersLines)
	// 5. collect all lines by order
	allLines := []string{dotformatting.DotHeader}
	allLines = append(allLines, groupPeersByNetwork(nsPeers, nsRepPeers, udnNsPeers)...)
	allLines = append(allLines, externalPeersLines...)
	allLines = append(allLines, edgeLines...)
	allLines = append(allLines, dotformatting.DotClosing)
	return strings.Join(allLines, newLineChar), nil
}

func groupPeersByNetwork(nsPeers, nsRepPeers, udnNsPeers map[string][]string) []string {
	lines := []string{}
	if len(udnNsPeers) == 0 { // no UDNs - keep original group by Namespaces - without network grouping
		lines = append(lines, dotformatting.AddNsGroups(nsPeers, dotformatting.DefaultNsGroupColor)...)
		lines = append(lines, dotformatting.AddNsGroups(nsRepPeers, representativeObjColor)...)
	} else {
		// 1. if there are regular namespaces : group by pods network
		if len(nsPeers) != 0 || len(nsRepPeers) != 0 {
			lines = []string{"\tsubgraph \"cluster_pod_network\" {", "\tlabel=\"pod network\""} // subgraph header + its label
			lines = append(lines, dotformatting.AddNsGroups(nsPeers, dotformatting.DefaultNsGroupColor)...)
			lines = append(lines, dotformatting.AddNsGroups(nsRepPeers, representativeObjColor)...)
			lines = append(lines, "\t}")
		}
		// 2. add UDN namespaces
		lines = append(lines, dotformatting.AddNsGroups(udnNsPeers, dotformatting.DefaultNsGroupColor)...)
	}
	return lines
}

// addConnlistOutputData updates namespace peers groups and returns edge lines and external peers lines from connlist results
func (d *formatDOT) addConnlistOutputData(conns []Peer2PeerConnection, nsPeers, udnNsPeers map[string][]string,
	peersVisited map[string]bool) (eLines, externalPeersLines []string) {
	edgeLines := make([]string, len(conns))
	for index := range conns {
		c := conns[index]
		connStr := common.ConnStrFromConnProperties(c.AllProtocolsAndPorts(), c.ProtocolsAndPorts())
		edgeLines[index] = dotformatting.GetEdgeLine(c.Src().String(), c.Dst().String(), connStr, connlistEdgeColor, edgeFontColor)
		externalPeersLines = append(externalPeersLines, addConnlistPeerLine(conns[index].Src(), nsPeers, udnNsPeers, peersVisited)...)
		externalPeersLines = append(externalPeersLines, addConnlistPeerLine(conns[index].Dst(), nsPeers, udnNsPeers, peersVisited)...)
	}
	for _, val := range d.peersList {
		if !val.IsPeerIPType() {
			externalPeersLines = append(externalPeersLines, addConnlistPeerLine(val, nsPeers, udnNsPeers, peersVisited)...)
		}
	}
	return edgeLines, externalPeersLines
}

// addConnlistPeerLine if the given peer is not visited yet, adds it to the relevant lines' group (namespace group/ external)
func addConnlistPeerLine(peer Peer, nsPeers, udnNsPeers map[string][]string, peersVisited map[string]bool) (externalPeerLine []string) {
	peerStr := peer.String()
	if !peersVisited[peerStr] {
		peersVisited[peerStr] = true
		peerLine, isExternalPeer, isInUDN := getPeerLine(peer)
		switch {
		case isExternalPeer: // peer that does not belong to the cluster (i.e. ip/ ingress-controller)
			externalPeerLine = []string{peerLine}
		case isInUDN: // in udn - add to the UDN namespaces
			dotformatting.AddPeerToNsGroup(peer.Namespace(), peerLine, udnNsPeers, isInUDN)
		default: // !isExternalPeer && !isInUDN - add to nsPeers Ns group (namespaces in the pods network)
			dotformatting.AddPeerToNsGroup(peer.Namespace(), peerLine, nsPeers, isInUDN)
		}
	}
	return externalPeerLine
}

// addExposureOutputData gets the exposure-analysis results, updates the namespaces peers groups lines for both real exposed peers and
// representative peers and returns the exposure edges and entire cluster line (as external peer line)
func addExposureOutputData(exposureConns []ExposedPeer, peersVisited map[string]bool,
	nsPeers, nsRepPeers map[string][]string) (entireClusterLine, exposureEdges []string) {
	representativeVisited := make(map[string]bool, 0) // acts as a set
	for _, ep := range exposureConns {
		if !peersVisited[ep.ExposedPeer().String()] { // an exposed peer is a real peer from the manifests,
			// updated in the real namespaces map
			exposedPeerLine, _, isInUDN := getPeerLine(ep.ExposedPeer())
			dotformatting.AddPeerToNsGroup(ep.ExposedPeer().Namespace(), exposedPeerLine, nsPeers, isInUDN)
		}
		ingressExpEdges := getXgressExposureEdges(ep.ExposedPeer().String(), ep.IngressExposure(), ep.IsProtectedByIngressNetpols(),
			true, representativeVisited, nsPeers, nsRepPeers)
		exposureEdges = append(exposureEdges, ingressExpEdges...)
		egressExpEdges := getXgressExposureEdges(ep.ExposedPeer().String(), ep.EgressExposure(), ep.IsProtectedByEgressNetpols(),
			false, representativeVisited, nsPeers, nsRepPeers)
		exposureEdges = append(exposureEdges, egressExpEdges...)
	}
	// if the entire-cluster marked as visited add its line too (this ensures the entire-cluster is added only once to the graph)
	if representativeVisited[entireCluster] {
		entireClusterLine = []string{getEntireClusterLine()}
	}
	return entireClusterLine, exposureEdges
}

// getXgressExposureEdges returns the edges' lines of the exposure data in the given direction ingress/egress
func getXgressExposureEdges(exposedPeerStr string, xgressExpData []XgressExposureData, isProtected, isIngress bool,
	representativeVisited map[string]bool, nsPeers, nsRepPeers map[string][]string) (xgressEdges []string) {
	if !isProtected { // a connection to entire cluster is enabled, (connection to all ips is already in the graph)
		representativeVisited[entireCluster] = true
		xgressEdges = append(xgressEdges, getExposureEdgeLine(exposedPeerStr, entireCluster, isIngress, common.MakeConnectionSet(true)))
	} else { // protected, having exposure details
		for _, data := range xgressExpData {
			if data.IsExposedToEntireCluster() {
				representativeVisited[entireCluster] = true
				xgressEdges = append(xgressEdges, getExposureEdgeLine(exposedPeerStr, entireCluster, isIngress,
					data.PotentialConnectivity().(*common.ConnectionSet)))
				continue // if a data contains exposure to entire cluster it does not specify labels
			}
			nsRepLabel := getRepresentativeNamespaceString(data.NamespaceLabels(), false)
			repPeerLabel := getRepresentativePodString(data.PodLabels(), false)
			repPeersStr := repPeerLabel + "_in_" + nsRepLabel // to get a unique string name of the peer node
			if !representativeVisited[repPeersStr] {
				representativeVisited[repPeersStr] = true
				peerLine := getRepPeerLine(repPeersStr, repPeerLabel)
				// ns label maybe a name of an existing namespace, so check where to add the peer
				if _, ok := nsPeers[nsRepLabel]; ok { // in real ns
					// @todo: add isInUDN check when supporting exposure-analysis with UDN
					dotformatting.AddPeerToNsGroup(nsRepLabel, peerLine, nsPeers, false)
				} else { // in a representative ns
					dotformatting.AddPeerToNsGroup(nsRepLabel, peerLine, nsRepPeers, false)
				}
			}
			xgressEdges = append(xgressEdges, getExposureEdgeLine(exposedPeerStr, repPeersStr, isIngress,
				data.PotentialConnectivity().(*common.ConnectionSet)))
		}
	}
	return xgressEdges
}

// getEntireClusterLine formats entire cluster line for dot graph
func getEntireClusterLine() string {
	return fmt.Sprintf(peerLineFormatPrefix+entireClusterShape+peerLineClosing, entireCluster, entireCluster, representativeObjColor,
		representativeObjColor)
}

// getExposureEdgeLine formats an exposure connection edge line for dot graph
func getExposureEdgeLine(realPeerStr, repPeerStr string, isIngress bool, conn *common.ConnectionSet) string {
	if isIngress {
		return fmt.Sprintf(dotformatting.EdgeLineFormat, repPeerStr, realPeerStr, conn.String(), ingressExposureEdgeColor, edgeFontColor,
			ingWeight, exposureEdgeStyle)
	}
	return fmt.Sprintf(dotformatting.EdgeLineFormat, realPeerStr, repPeerStr, conn.String(), egressExposureEdgeColor, edgeFontColor,
		egWeight, exposureEdgeStyle)
}

// getRepPeerLine formats a representative peer line for dot graph
func getRepPeerLine(peerStr, peerLabel string) string {
	return fmt.Sprintf(peerLineFormatPrefix+peerLineClosing, peerStr, peerLabel, representativeObjColor, representativeObjColor)
}
