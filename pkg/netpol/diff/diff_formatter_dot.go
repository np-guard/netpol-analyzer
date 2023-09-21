package diff

import (
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/common"
)

// diffFormatDOT: implements the diffFormatter interface for dot output format
type diffFormatDOT struct {
}

// writeDiffOutput writes the diff output in the dot format
func (df *diffFormatDOT) writeDiffOutput(connsDiff ConnectivityDiff) (string, error) {
	var edgeLines, peersLines, ingressAnalyzerEdges []string
	peersVisited := make(map[string]bool, 0) // set of peers
	// non changed
	ncPeers, nonChangedEdges, nonChangedIngressEdges := getEdgesAndPeersLinesByCategory(connsDiff.NonChangedConnections(), peersVisited)
	peersLines = append(peersLines, ncPeers...)
	edgeLines = append(edgeLines, nonChangedEdges...)
	ingressAnalyzerEdges = append(ingressAnalyzerEdges, nonChangedIngressEdges...)
	// changed
	cPeers, changedEedges, changedIngressEdges := getEdgesAndPeersLinesByCategory(connsDiff.ChangedConnections(), peersVisited)
	peersLines = append(peersLines, cPeers...)
	edgeLines = append(edgeLines, changedEedges...)
	ingressAnalyzerEdges = append(ingressAnalyzerEdges, changedIngressEdges...)
	// added
	nPeers, newEdges, newIngressEdges := getEdgesAndPeersLinesByCategory(connsDiff.AddedConnections(), peersVisited)
	peersLines = append(peersLines, nPeers...)
	edgeLines = append(edgeLines, newEdges...)
	ingressAnalyzerEdges = append(ingressAnalyzerEdges, newIngressEdges...)
	// removed
	lPeers, lostEdges, lostIngressEdges := getEdgesAndPeersLinesByCategory(connsDiff.RemovedConnections(), peersVisited)
	peersLines = append(peersLines, lPeers...)
	edgeLines = append(edgeLines, lostEdges...)
	ingressAnalyzerEdges = append(ingressAnalyzerEdges, lostIngressEdges...)

	// sort lines
	sort.Strings(peersLines)
	sort.Strings(edgeLines)
	sort.Strings(ingressAnalyzerEdges)

	// write graph
	allLines := []string{common.DotHeader}
	allLines = append(allLines, peersLines...)
	allLines = append(allLines, edgeLines...)
	allLines = append(allLines, ingressAnalyzerEdges...)
	allLines = append(allLines, common.DotClosing)
	return strings.Join(allLines, newLine), nil
}

// getEdgesAndPeersLinesByCategory returns the dot peers, edges and  ingress edges lines of the given connsPairs
// (all connsPairs are in same category)
func getEdgesAndPeersLinesByCategory(connsPairs []*ConnsPair, peersSet map[string]bool) (peersLines, connsEdges, ingressEdges []string) {
	peersLines = make([]string, 0)
	connsEdges = make([]string, 0)
	ingressEdges = make([]string, 0)
	for _, connsPair := range connsPairs {
		src, dst, isIngress := getConnPeersStrings(connsPair)
		// add peers lines (which are still not in the set)
		if !peersSet[src] {
			peersSet[src] = true
			peersLines = append(peersLines, addPeerLine(src, connsPair.diffType, connsPair.newOrLostSrc))
		}
		if !peersSet[dst] {
			peersSet[dst] = true
			peersLines = append(peersLines, addPeerLine(dst, connsPair.diffType, connsPair.newOrLostDst))
		}
		// add connections lines
		if isIngress {
			ingressEdges = append(ingressEdges, addEdgesLines(connsPair))
		} else {
			connsEdges = append(connsEdges, addEdgesLines(connsPair))
		}
	}
	return peersLines, connsEdges, ingressEdges
}

const (
	newPeerColor        = "green3"
	removedPeerColor    = "red"
	persistentPeerColor = "blue"
)

// addPeerLine returns peer line string in dot format
func addPeerLine(peerName, diffType string, isNewOrLost bool) string {
	peerColor := persistentPeerColor
	if isNewOrLost {
		switch diffType {
		case addedType:
			peerColor = newPeerColor
		case removedType:
			peerColor = removedPeerColor
		default: // will not get here
			break
		}
	}
	return fmt.Sprintf("\t%q [label=%q color=%q fontcolor=%q]", peerName, peerName, peerColor, peerColor)
}

const (
	nonChangedConnColor = "grey"
	changedConnColor    = "gold2"
	removedConnColor    = "red2"
	addedConnColor      = "green"
)

// addEdgesLines forms the appropriate edge line of the given conns pair
func addEdgesLines(connsPair *ConnsPair) string {
	src, dst, _ := getConnPeersStrings(connsPair)
	firstConn, secondConn := getDirsConnsStrings(connsPair)
	switch connsPair.diffType {
	case nonChangedType:
		return getEdgeLine(src, dst, firstConn, nonChangedConnColor)
	case changedType:
		changedEdgeLabel := secondConn + " (was: " + firstConn + ")"
		return getEdgeLine(src, dst, changedEdgeLabel, changedConnColor)
	case removedType:
		return getEdgeLine(src, dst, firstConn, removedConnColor)
	case addedType:
		return getEdgeLine(src, dst, secondConn, addedConnColor)
	default:
		return "" // should not get here
	}
}

// getEdgeLine returns a single edge line string in the dot format
func getEdgeLine(src, dst, connStr, edgeColor string) string {
	return fmt.Sprintf("\t%q -> %q [label=%q color=%q fontcolor=%q]", src, dst, connStr, edgeColor, edgeColor)
}

// kept empty for dot format, used to implement the diffFormatter interface in other formats
func (df *diffFormatDOT) singleDiffLine(d *singleDiffFields) string {
	return ""
}
