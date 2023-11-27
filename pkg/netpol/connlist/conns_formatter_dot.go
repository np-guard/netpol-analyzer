package connlist

import (
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

const (
	ipColor     = "red2"
	nsPeerColor = "blue"
)

// formatDOT: implements the connsFormatter interface for dot output format
type formatDOT struct {
}

// formats an edge line from a singleConnFields struct , to be used for dot graph
func getEdgeLine(c Peer2PeerConnection) string {
	connStr := common.ConnStrFromConnProperties(c.AllProtocolsAndPorts(), c.ProtocolsAndPorts())
	srcName, _ := peerNameAndColorByType(c.Src())
	dstName, _ := peerNameAndColorByType(c.Dst())
	return fmt.Sprintf("\t%q -> %q [label=%q color=\"gold2\" fontcolor=\"darkgreen\"]", srcName, dstName, connStr)
}

func peerNameAndColorByType(peer Peer) (name, color string) {
	if peer.IsPeerIPType() {
		return peer.String(), ipColor
	} else if peer.Name() == common.IngressPodName {
		return peer.String(), nsPeerColor
	}
	return peer.Name(), nsPeerColor
}

// formats a peer line for dot graph
func getPeerLine(peer Peer) string {
	peerName, peerColor := peerNameAndColorByType(peer)
	return fmt.Sprintf("\t\t%q [label=%q color=%q fontcolor=%q]", peerName, peerName, peerColor, peerColor)
}

// returns a dot string form of connections from list of Peer2PeerConnection objects
func (d formatDOT) writeOutput(conns []Peer2PeerConnection) (string, error) {
	nsPeers := make(map[string][]string)         // map from namespace to its peers (grouping peers by namespaces)
	edgeLines := make([]string, len(conns))      // list of edges lines
	peersVisited := make(map[string]struct{}, 0) // acts as a set
	for index := range conns {
		srcStr, dstStr := conns[index].Src().String(), conns[index].Dst().String()
		edgeLines[index] = getEdgeLine(conns[index])
		if _, ok := peersVisited[srcStr]; !ok {
			peersVisited[srcStr] = struct{}{}
			checkAndAddPeerToNsGroup(nsPeers, conns[index].Src())
		}
		if _, ok := peersVisited[dstStr]; !ok {
			peersVisited[dstStr] = struct{}{}
			checkAndAddPeerToNsGroup(nsPeers, conns[index].Dst())
		}
	}
	// sort graph lines
	sort.Strings(edgeLines)
	// collect all lines by order
	allLines := []string{common.DotHeader}
	allLines = append(allLines, addNsGroups(nsPeers)...)
	allLines = append(allLines, edgeLines...)
	allLines = append(allLines, common.DotClosing)
	return strings.Join(allLines, newLineChar), nil
}

func checkAndAddPeerToNsGroup(mapNsToPeers map[string][]string, peer Peer) {
	if _, ok := mapNsToPeers[peer.Namespace()]; !ok {
		mapNsToPeers[peer.Namespace()] = []string{}
	}
	mapNsToPeers[peer.Namespace()] = append(mapNsToPeers[peer.Namespace()], getPeerLine(peer))
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
		nsLabel := strings.ReplaceAll(ns, "-", "_")
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
