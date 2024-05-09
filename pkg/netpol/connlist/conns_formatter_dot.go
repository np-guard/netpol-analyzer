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
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/dotformatting"
)

const (
	ipColor                = "red2"
	nonIPPeerColor         = "blue"
	representativeObjColor = "red2"
	entireClusterShape     = " shape=diamond"
	peerLineClosing        = "]"
	allPeersLbl            = "all pods"
	allNamespacesLbl       = "all namespaces"
)

var edgeLineFormat = fmt.Sprintf("\t%%q -> %%q [label=%%q color=\"gold2\" fontcolor=\"darkgreen\"]")
var peerLineFormatPrefix = fmt.Sprintf("\t%%q [label=%%q color=%%q fontcolor=%%q")

// formatDOT: implements the connsFormatter interface for dot output format
type formatDOT struct {
}

// getEdgeLine formats an edge line from a Peer2PeerConnection struct , to be used for dot graph
func getEdgeLine(c Peer2PeerConnection) string {
	connStr := common.ConnStrFromConnProperties(c.AllProtocolsAndPorts(), c.ProtocolsAndPorts())
	return fmt.Sprintf(edgeLineFormat, c.Src().String(), c.Dst().String(), connStr)
}

// peerNameAndColorByType returns the peer label and color to be represented in the graph, and whether the peer is
// external to cluster's namespaces
func peerNameAndColorByType(peer Peer) (nameLabel, color string, isExternal bool) {
	if peer.IsPeerIPType() {
		return peer.String(), ipColor, true
	} else if peer.Name() == common.IngressPodName {
		return peer.String(), nonIPPeerColor, true
	}
	return dotformatting.NodeClusterPeerLabel(peer.Name(), peer.Kind()), nonIPPeerColor, false
}

// getPeerLine formats a peer line for dot graph
func getPeerLine(peer Peer) (string, bool) {
	peerNameLabel, peerColor, isExternalPeer := peerNameAndColorByType(peer)
	return fmt.Sprintf(peerLineFormatPrefix+peerLineClosing, peer.String(), peerNameLabel, peerColor, peerColor), isExternalPeer
}

// returns a dot string form of connections from list of Peer2PeerConnection objects
// and from exposure-analysis results if exists
func (d *formatDOT) writeOutput(conns []Peer2PeerConnection, exposureConns []ExposedPeer) (string, error) {
	// 1. declaration of maps and slices to be used for forming the graph lines
	nsPeers := make(map[string][]string)     // map from namespace to its peers (grouping peers by namespaces)
	nsRepPeers := make(map[string][]string)  // map from representative namespace to its representative peers
	externalPeersLines := make([]string, 0)  // list of peers which are not in a cluster's namespace (will not be grouped)
	edgeLines := make([]string, 0)           // list of edges lines (connections of connlist + exposure)
	peersVisited := make(map[string]bool, 0) // acts as a set
	// 2. add connlist results to the graph lines
	connsEdges, connsExternalPeers := addConnlistOutputData(conns, nsPeers, peersVisited)
	edgeLines = append(edgeLines, connsEdges...)
	externalPeersLines = append(externalPeersLines, connsExternalPeers...)
	// 3. add exposure-analysis results to the graph lines
	entireClusterLine, exposureEdges := addExposureOutputData(exposureConns, peersVisited, nsPeers, nsRepPeers)
	externalPeersLines = append(externalPeersLines, entireClusterLine...)
	edgeLines = append(edgeLines, exposureEdges...)
	// 4. sort graph lines
	sort.Strings(edgeLines)
	sort.Strings(externalPeersLines)
	// 5. collect all lines by order
	allLines := []string{dotformatting.DotHeader}
	allLines = append(allLines, dotformatting.AddNsGroups(nsPeers, dotformatting.DefaultNsGroupColor)...)
	allLines = append(allLines, dotformatting.AddNsGroups(nsRepPeers, representativeObjColor)...)
	allLines = append(allLines, externalPeersLines...)
	allLines = append(allLines, edgeLines...)
	allLines = append(allLines, dotformatting.DotClosing)
	return strings.Join(allLines, newLineChar), nil
}

// addConnlistOutputData updates namespace peers groups and returns edge lines and external peers lines from connlist results
func addConnlistOutputData(conns []Peer2PeerConnection, nsPeers map[string][]string,
	peersVisited map[string]bool) (eLines, externalPeersLines []string) {
	edgeLines := make([]string, len(conns))
	for index := range conns {
		edgeLines[index] = getEdgeLine(conns[index])
		externalPeersLines = append(externalPeersLines, addConnlistPeerLine(conns[index].Src(), nsPeers, peersVisited)...)
		externalPeersLines = append(externalPeersLines, addConnlistPeerLine(conns[index].Dst(), nsPeers, peersVisited)...)
	}
	return edgeLines, externalPeersLines
}

// addConnlistPeerLine if the given peer is not visited yet, adds it to the relevant lines' group (namespace group/ external)
func addConnlistPeerLine(peer Peer, nsPeers map[string][]string, peersVisited map[string]bool) (externalPeerLine []string) {
	if !peersVisited[peer.String()] {
		peersVisited[peer.String()] = true
		peerLine, isExternalPeer := getPeerLine(peer)
		if isExternalPeer { // peer that does not belong to a cluster's namespace (i.e. ip/ ingress-controller)
			externalPeerLine = []string{peerLine}
		} else { // add to Ns group
			dotformatting.AddPeerToNsGroup(peer.Namespace(), peerLine, nsPeers)
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
			exposedPeerLine, _ := getPeerLine(ep.ExposedPeer())
			dotformatting.AddPeerToNsGroup(ep.ExposedPeer().Namespace(), exposedPeerLine, nsPeers)
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
			nsRepLabel := getRepresentativeNamespaceString(data.NamespaceLabels())
			repPeerLabel := getRepresentativePodString(data.PodLabels())
			repPeersStr := repPeerLabel + "_in_" + nsRepLabel // to get a unique string name of the peer node
			if !representativeVisited[repPeersStr] {
				representativeVisited[repPeersStr] = true
				peerLine := getRepPeerLine(repPeersStr, repPeerLabel)
				// ns label maybe a name of an existing namespace, so check where to add the peer
				if _, ok := nsPeers[nsRepLabel]; ok { // in real ns
					dotformatting.AddPeerToNsGroup(getRepresentativeNamespaceString(data.NamespaceLabels()), peerLine, nsPeers)
				} else { // in a representative ns
					dotformatting.AddPeerToNsGroup(getRepresentativeNamespaceString(data.NamespaceLabels()), peerLine, nsRepPeers)
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
		return fmt.Sprintf(edgeLineFormat, repPeerStr, realPeerStr, conn.String())
	}
	return fmt.Sprintf(edgeLineFormat, realPeerStr, repPeerStr, conn.String())
}

// getRepPeerLine formats a representative peer line for dot graph
func getRepPeerLine(peerStr, peerLabel string) string {
	return fmt.Sprintf(peerLineFormatPrefix+peerLineClosing, peerStr, peerLabel, representativeObjColor, representativeObjColor)
}
