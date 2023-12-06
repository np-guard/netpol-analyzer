package connlist

import (
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

const (
	ipColor        = "red2"
	nonIPPeerColor = "blue"
)

// formatDOT: implements the connsFormatter interface for dot output format
type formatDOT struct {
}

// formats an edge line from a singleConnFields struct , to be used for dot graph
func getEdgeLine(c Peer2PeerConnection) string {
	connStr := common.ConnStrFromConnProperties(c.AllProtocolsAndPorts(), c.ProtocolsAndPorts())
	srcName, _, _ := peerNameAndColorByType(c.Src())
	dstName, _, _ := peerNameAndColorByType(c.Dst())
	return fmt.Sprintf("\t%q -> %q [label=%q color=\"gold2\" fontcolor=\"darkgreen\"]", srcName, dstName, connStr)
}

// returns the peer name and color to be represented in the graph, and whether the peer is external to cluster's namespaces
func peerNameAndColorByType(peer Peer) (name, color string, isExternal bool) {
	if peer.IsPeerIPType() {
		return peer.String(), ipColor, true
	} else if peer.Name() == common.IngressPodName {
		return peer.String(), nonIPPeerColor, true
	}
	return peer.Name() + "[" + peer.Kind() + "]", nonIPPeerColor, false
}

// formats a peer line for dot graph
func getPeerLine(peer Peer) (string, bool) {
	peerName, peerColor, isExternalPeer := peerNameAndColorByType(peer)
	linePrefix := "\t\t"
	if isExternalPeer {
		linePrefix = "\t"
	}
	return fmt.Sprintf("%s%q [label=%q color=%q fontcolor=%q]", linePrefix, peerName, peerName, peerColor, peerColor), isExternalPeer
}

// returns a dot string form of connections from list of Peer2PeerConnection objects
func (d formatDOT) writeOutput(conns []Peer2PeerConnection) (string, error) {
	nsPeers := make(map[string][]string)         // map from namespace to its peers (grouping peers by namespaces)
	externalPeersLines := make([]string, 0)      // list of peers which are not in a cluster's namespace (will not be grouped)
	edgeLines := make([]string, len(conns))      // list of edges lines
	peersVisited := make(map[string]struct{}, 0) // acts as a set
	for index := range conns {
		srcStr, dstStr := conns[index].Src().String(), conns[index].Dst().String()
		edgeLines[index] = getEdgeLine(conns[index])
		if _, ok := peersVisited[srcStr]; !ok {
			peersVisited[srcStr] = struct{}{}
			externalSrcLine := checkAndAddPeerToNsGroup(nsPeers, conns[index].Src())
			if externalSrcLine != "" {
				externalPeersLines = append(externalPeersLines, externalSrcLine)
			}
		}
		if _, ok := peersVisited[dstStr]; !ok {
			peersVisited[dstStr] = struct{}{}
			externalDstLine := checkAndAddPeerToNsGroup(nsPeers, conns[index].Dst())
			if externalDstLine != "" {
				externalPeersLines = append(externalPeersLines, externalDstLine)
			}
		}
	}
	// sort graph lines
	sort.Strings(edgeLines)
	sort.Strings(externalPeersLines)
	// collect all lines by order
	allLines := []string{common.DotHeader}
	allLines = append(allLines, addNsGroups(nsPeers)...)
	allLines = append(allLines, externalPeersLines...)
	allLines = append(allLines, edgeLines...)
	allLines = append(allLines, common.DotClosing)
	return strings.Join(allLines, newLineChar), nil
}

// checks if the peer is in cluster's namespace, then adds its line to the namespace list in the given map.
// else, returns its line to be added to the external peers lines
func checkAndAddPeerToNsGroup(mapNsToPeers map[string][]string, peer Peer) string {
	peerLine, isExternalPeer := getPeerLine(peer)
	if !isExternalPeer { // belongs to a cluster's namespace
		if _, ok := mapNsToPeers[peer.Namespace()]; !ok {
			mapNsToPeers[peer.Namespace()] = []string{}
		}
		mapNsToPeers[peer.Namespace()] = append(mapNsToPeers[peer.Namespace()], peerLine)
		return ""
	}
	// else case - an external (ip/ ingress-controller) peer
	return peerLine
}

func addNsGroups(nsPeersMap map[string][]string) []string {
	res := []string{}
	// sort namespaces (map's keys) to ensure same output always
	nsKeys := sortMapKeys(nsPeersMap)
	// write ns groups
	for _, ns := range nsKeys {
		peersLines := nsPeersMap[ns]
		sort.Strings(peersLines)
		// create ns  subgraph cluster
		nsLabel := strings.ReplaceAll(ns, "-", "_") // dot format does not accept "-" in its sub-graphs names (headers)
		nsLines := []string{"\tsubgraph cluster_" + nsLabel + " {"} // subgraph header
		nsLines = append(nsLines, peersLines...)
		nsLines = append(nsLines, "\t\tlabel=\""+ns+"\"", "\t}")
		// add ns section to the res
		res = append(res, nsLines...)
	}
	return res
}

func sortMapKeys(nsPeersMap map[string][]string) []string {
	keys := make([]string, 0, len(nsPeersMap))
	for k := range nsPeersMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
