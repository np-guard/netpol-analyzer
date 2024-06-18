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
	ipColor        = "red2"
	nonIPPeerColor = "blue"
)

// formatDOT: implements the connsFormatter interface for dot output format
type formatDOT struct {
	peersList []Peer // internally used peersList; in case of focusWorkload option contains only relevant peers
}

// formats an edge line from a singleConnFields struct , to be used for dot graph
func getEdgeLine(c Peer2PeerConnection) string {
	connStr := common.ConnStrFromConnProperties(c.AllProtocolsAndPorts(), c.ProtocolsAndPorts())
	return fmt.Sprintf("\t%q -> %q [label=%q color=\"gold2\" fontcolor=\"darkgreen\"]", c.Src().String(), c.Dst().String(), connStr)
}

// returns the peer label and color to be represented in the graph, and whether the peer is external to cluster's namespaces
func peerNameAndColorByType(peer Peer) (nameLabel, color string, isExternal bool) {
	if peer.IsPeerIPType() {
		return peer.String(), ipColor, true
	} else if peer.Name() == common.IngressPodName {
		return peer.String(), nonIPPeerColor, true
	}
	return dotformatting.NodeClusterPeerLabel(peer.Name(), peer.Kind()), nonIPPeerColor, false
}

// formats a peer line for dot graph
func getPeerLine(peer Peer) (string, bool) {
	peerNameLabel, peerColor, isExternalPeer := peerNameAndColorByType(peer)
	return fmt.Sprintf("\t%q [label=%q color=%q fontcolor=%q]", peer.String(), peerNameLabel, peerColor, peerColor), isExternalPeer
}

func categorizeAndAddPeerLine(peer Peer, peersVisited map[string]bool, externalPeersLines []string, nsPeers map[string][]string) []string {
	peerStr := peer.String()
	if !peersVisited[peerStr] {
		peersVisited[peerStr] = true
		peerLine, isExternalPeer := getPeerLine(peer)
		if isExternalPeer { // peer that does not belong to a cluster's namespace (i.e. ip/ ingress-controller)
			externalPeersLines = append(externalPeersLines, peerLine)
		} else { // add to Ns group
			dotformatting.AddPeerToNsGroup(peer.Namespace(), peerLine, nsPeers)
		}
	}
	return externalPeersLines
}

// returns a dot string form of connections from list of Peer2PeerConnection objects
func (d formatDOT) writeOutput(conns []Peer2PeerConnection) (string, error) {
	nsPeers := make(map[string][]string)     // map from namespace to its peers (grouping peers by namespaces)
	externalPeersLines := make([]string, 0)  // list of peers which are not in a cluster's namespace (will not be grouped)
	edgeLines := make([]string, len(conns))  // list of edges lines
	peersVisited := make(map[string]bool, 0) // acts as a set
	for index := range conns {
		edgeLines[index] = getEdgeLine(conns[index])
		externalPeersLines = categorizeAndAddPeerLine(conns[index].Src(), peersVisited, externalPeersLines, nsPeers)
		externalPeersLines = categorizeAndAddPeerLine(conns[index].Dst(), peersVisited, externalPeersLines, nsPeers)
	}
	for _, val := range d.peersList {
		if !val.IsPeerIPType() {
			externalPeersLines = categorizeAndAddPeerLine(val, peersVisited, externalPeersLines, nsPeers)
		}
	}

	// sort graph lines
	sort.Strings(edgeLines)
	sort.Strings(externalPeersLines)
	// collect all lines by order
	allLines := []string{dotformatting.DotHeader}
	allLines = append(allLines, dotformatting.AddNsGroups(nsPeers)...)
	allLines = append(allLines, externalPeersLines...)
	allLines = append(allLines, edgeLines...)
	allLines = append(allLines, dotformatting.DotClosing)
	return strings.Join(allLines, newLineChar), nil
}
