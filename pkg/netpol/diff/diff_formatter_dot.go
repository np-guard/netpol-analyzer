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
	allLines = append(allLines, addLegend()...)
	allLines = append(allLines, common.DotClosing)
	return strings.Join(allLines, newLine), nil
}

// getEdgesAndPeersLinesByCategory returns the dot peers, edges and  ingress edges lines of the given connsPairs
// (all connsPairs are in same category)
func getEdgesAndPeersLinesByCategory(connsPairs []SrcDstDiff, peersSet map[string]bool) (peersLines, connsEdges, ingressEdges []string) {
	peersLines = make([]string, 0)
	connsEdges = make([]string, 0)
	ingressEdges = make([]string, 0)
	for _, connsPair := range connsPairs {
		src, dst, isIngress := getConnPeersStrings(connsPair)
		// add peers lines (which are still not in the set)
		if !peersSet[src] {
			peersSet[src] = true
			peersLines = append(peersLines, addPeerLine(src, connsPair.DiffType(), connsPair.IsSrcNewOrRemoved()))
		}
		if !peersSet[dst] {
			peersSet[dst] = true
			peersLines = append(peersLines, addPeerLine(dst, connsPair.DiffType(), connsPair.IsDstNewOrRemoved()))
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
	newPeerColor        = "#008000" // svg green
	removedPeerColor    = "red"
	persistentPeerColor = "blue"
)

// addPeerLine returns peer line string in dot format
func addPeerLine(peerName string, diffType DiffTypeStr, isNewOrLost bool) string {
	peerColor := persistentPeerColor
	if isNewOrLost {
		switch diffType {
		case AddedType:
			peerColor = newPeerColor
		case RemovedType:
			peerColor = removedPeerColor
		default: // will not get here
			break
		}
	}
	return fmt.Sprintf("\t%q [label=%q color=%q fontcolor=%q]", peerName, peerName, peerColor, peerColor)
}

const (
	nonChangedConnColor = "grey"
	changedConnColor    = "magenta"
	removedConnColor    = "red2"
	addedConnColor      = "#008000"
)

// addEdgesLines forms the appropriate edge line of the given conns pair
func addEdgesLines(connsPair SrcDstDiff) string {
	src, dst, _ := getConnPeersStrings(connsPair)
	firstConn, secondConn := getDirsConnsStrings(connsPair)
	switch connsPair.DiffType() {
	case NonChangedType:
		return getEdgeLine(src, dst, firstConn, nonChangedConnColor)
	case ChangedType:
		changedEdgeLabel := secondConn + " (old: " + firstConn + ")"
		return getEdgeLine(src, dst, changedEdgeLabel, changedConnColor)
	case RemovedType:
		return getEdgeLine(src, dst, firstConn, removedConnColor)
	case AddedType:
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

// writing a legend
// all functions in this section are const and uses const variables

// creates legend lines
func addLegend() []string { // const
	legendLines := []string{}
	legendLines = append(legendLines, addLegendDetails()...)
	legendLines = append(legendLines, addInvisibleCharsLines()...)
	legendLines = append(legendLines, addEdgeKeyLines()...)
	legendLines = append(legendLines, addNodeKeyLines()...)
	legendLines = append(legendLines, legendClosing)
	return legendLines
}

const (
	graphNodeSep         = "\tnodesep=0.5"
	legendHeader         = "\tsubgraph cluster_legend {"
	legendClosing        = "\t}"
	legendLabel          = "Legend"
	legendRankSinkLine   = "rank=sink"
	legendRankSameLine   = "rank=same"
	legendRankSourceLine = "rank=source"
	legendColorLine      = "node [ color=\"white\" ]"
	legendFontSize       = "fontsize = 10"
	legendMargin         = "margin=0"
	invisibleStr         = "style=invis"
	heightStr            = "height=0"
	widthStr             = "width=0"
	linePrefix           = "\t\t"
	colorStr             = "color"
	labelStr             = "label"
	addedEdgeLabel       = "added connection"
	removedEdgeLabel     = "removed connection"
	changedEdgeLabel     = "changed connection"
	nonChangedEdgeLabel  = "unchanged connection"
	newPeerLabel         = "new peer"
	lostPeerLabel        = "lost peer"
	persistentPeerLabel  = "persistent peer"
	fontColorStr         = "fontcolor"
	legendArrowSize      = "arrowsize=0.2"
	listOpen             = "{"
	listClose            = "}"
)

func addLegendDetails() []string {
	res := []string{
		graphNodeSep,
		legendHeader,
		fmt.Sprintf(linePrefix+"%s=%q", labelStr, legendLabel),
		linePrefix + legendFontSize,
		linePrefix + legendMargin,
	}
	return res
}

var invisibleNodes = []string{"a", "b", "c", "d", "e", "f", "g", "h"}

func addInvisibleCharsLines() []string { // const
	res := []string{}
	for _, val := range invisibleNodes {
		res = append(res, fmt.Sprintf(linePrefix+"%s [%s %s %s]", val, invisibleStr, heightStr, widthStr))
	}
	return res
}

func addSingleEdgeKey(src, dst, edgeLabel, edgeColor string) string {
	return fmt.Sprintf(linePrefix+"%s -> %s [%s=%q, %s=%q %s=%q %s %s]", src, dst, labelStr, edgeLabel, colorStr,
		edgeColor, fontColorStr, edgeColor, legendFontSize, legendArrowSize)
}

//nolint:revive // temporary work around
func addEdgeKeyLines() []string { // const
	res := []string{
		linePrefix + listOpen + legendRankSourceLine + space + strings.Join(invisibleNodes[0:4], space) + listClose,
		linePrefix + listOpen + legendRankSameLine + space + strings.Join(invisibleNodes[4:], space) + listClose,
		addSingleEdgeKey(invisibleNodes[0], invisibleNodes[1], addedEdgeLabel, addedConnColor),
		addSingleEdgeKey(invisibleNodes[2], invisibleNodes[3], removedEdgeLabel, removedConnColor),
		addSingleEdgeKey(invisibleNodes[4], invisibleNodes[5], changedEdgeLabel, changedConnColor),
		addSingleEdgeKey(invisibleNodes[6], invisibleNodes[7], nonChangedEdgeLabel, nonChangedConnColor)}
	return res
}

var pNodesNames = []string{"np", "lp", "pp"}

func addSingleNodeLine(nodeName, nodeLabel, nodeColor string) string {
	return fmt.Sprintf(linePrefix+"%s [%s=%q %s=%q %s=%q %s]", nodeName, labelStr, nodeLabel, colorStr,
		nodeColor, fontColorStr, nodeColor, legendFontSize)
}

func addInvisibleEdges() []string {
	res := []string{}
	for i := 0; i < len(pNodesNames)-1; i++ {
		res = append(res, fmt.Sprintf(linePrefix+"%s->%s [%s]", pNodesNames[i], pNodesNames[i+1], invisibleStr))
	}
	return res
}

func addNodeKeyLines() []string { // const
	res := []string{addSingleNodeLine(pNodesNames[0], newPeerLabel, newPeerColor),
		addSingleNodeLine(pNodesNames[1], lostPeerLabel, removedPeerColor),
		addSingleNodeLine(pNodesNames[2], persistentPeerLabel, persistentPeerColor),
		linePrefix + listOpen + legendRankSinkLine + space + strings.Join(pNodesNames, space) + listClose}
	res = append(res, addInvisibleEdges()...)
	return res
}
