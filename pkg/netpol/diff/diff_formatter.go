package diff

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/connlist"
)

// diffFormatter implements diff output formatting in the required output format
type diffFormatter interface {
	writeDiffOutput(connsDiff ConnectivityDiff) (string, error)
	singleDiffLine(d *singleDiffFields) string
}

const (
	noConns    = "No Connections"
	infoPrefix = "workload "
	space      = " "
	and        = " and "
)

var newLine = fmt.Sprintln("")

type singleDiffFields struct {
	diffType         string
	src              string
	dst              string
	dir1Conn         string
	dir2Conn         string
	workloadDiffInfo string
}

func formDiffFieldsDataOfDiffConns(diffConns []*ConnsPair) (netpolsDiff, ingressDiff []*singleDiffFields) {
	netpolsRes := make([]*singleDiffFields, 0) // diff in connections from netpols
	ingressRes := make([]*singleDiffFields, 0) // diff in connections from ingress-controller
	for _, d := range diffConns {
		firstDirConn, secondDirConn := getDirsConnsStrings(d)
		srcStr, dstStr, isSrcIngress := getConnPeersStrings(d)
		diffData := &singleDiffFields{
			diffType:         d.diffType,
			src:              srcStr,
			dst:              dstStr,
			dir1Conn:         firstDirConn,
			dir2Conn:         secondDirConn,
			workloadDiffInfo: getDiffInfo(d),
		}
		if isSrcIngress {
			ingressRes = append(ingressRes, diffData)
		} else {
			netpolsRes = append(netpolsRes, diffData)
		}
	}
	return netpolsRes, ingressRes
}

func getConnPeersStrings(c *ConnsPair) (srcStr, dstStr string, isSrcIngress bool) {
	switch c.diffType {
	case changedType, removedType, nonChangedType:
		return c.firstConn.Src().String(), c.firstConn.Dst().String(), isIngressControllerPeer(c.firstConn.Src())
	case addedType:
		return c.secondConn.Src().String(), c.secondConn.Dst().String(), isIngressControllerPeer(c.secondConn.Src())
	default:
		return "", "", false // should not get here
	}
}
func getDirsConnsStrings(c *ConnsPair) (dir1Str, dir2Str string) {
	switch c.diffType {
	case changedType, nonChangedType:
		return connlist.GetProtocolsAndPortsStr(c.firstConn), connlist.GetProtocolsAndPortsStr(c.secondConn)
	case addedType:
		return noConns, connlist.GetProtocolsAndPortsStr(c.secondConn)
	case removedType:
		return connlist.GetProtocolsAndPortsStr(c.firstConn), noConns
	default:
		return "", "" // should not get here ever
	}
}

// computes the diff string (if to include added/removed workloads)
func getDiffInfo(c *ConnsPair) string {
	srcStr, dstStr, _ := getConnPeersStrings(c)
	diffInfo := ""
	// handling added or removed diff data
	includedSrcFlag := false
	if c.newOrLostSrc || c.newOrLostDst {
		diffInfo += infoPrefix
		if c.newOrLostSrc {
			diffInfo += srcStr
			includedSrcFlag = true
		}
		if c.newOrLostDst {
			if includedSrcFlag {
				diffInfo += and
			}
			diffInfo += dstStr
		}
		diffInfo += space + c.diffType
	}
	return diffInfo
}

func writeDiffLinesOrderedByCategory(connsDiff ConnectivityDiff, df diffFormatter) []string {
	res := make([]string, 0)
	// changed lines
	netpolsChanged, ingressChanged := formDiffFieldsDataOfDiffConns(connsDiff.ChangedConnections())
	changedNetpolsLines := writeDiffLines(netpolsChanged, df)
	changedIngressLines := writeDiffLines(ingressChanged, df)
	// added lines
	netpolsAdded, ingressAdded := formDiffFieldsDataOfDiffConns(connsDiff.AddedConnections())
	addedNetpolsLines := writeDiffLines(netpolsAdded, df)
	addedIngressLines := writeDiffLines(ingressAdded, df)
	// removed lines
	netpolsRemoved, ingressRemoved := formDiffFieldsDataOfDiffConns(connsDiff.RemovedConnections())
	removedNetpolsLines := writeDiffLines(netpolsRemoved, df)
	removedIngressLines := writeDiffLines(ingressRemoved, df)

	// first write lines of netpols connectivity diff
	res = append(res, changedNetpolsLines...)
	res = append(res, addedNetpolsLines...)
	res = append(res, removedNetpolsLines...)
	// then append lines of ingress diff
	res = append(res, changedIngressLines...)
	res = append(res, addedIngressLines...)
	res = append(res, removedIngressLines...)

	return res
}

func writeDiffLines(diffData []*singleDiffFields, df diffFormatter) []string {
	res := make([]string, len(diffData))
	for i, singleDiffData := range diffData {
		res[i] = df.singleDiffLine(singleDiffData)
	}
	sort.Strings(res)
	return res
}

// /////////////////////////
// diffFormatText: implements the diffFormatter interface for txt output format
type diffFormatText struct {
}

const (
	// txt output header
	connectivityDiffHeader = "Connectivity diff:"
)

// returns a textual string format of connections diff from connectivityDiff object
func (t *diffFormatText) writeDiffOutput(connsDiff ConnectivityDiff) (string, error) {
	res := make([]string, 0)
	res = append(res, connectivityDiffHeader)
	res = append(res, writeDiffLinesOrderedByCategory(connsDiff, t)...)
	return strings.Join(res, newLine), nil
}

func (t *diffFormatText) singleDiffLine(d *singleDiffFields) string {
	diffLine := fmt.Sprintf("diff-type: %s, source: %s, destination: %s, dir1:  %s, dir2: %s", d.diffType,
		d.src, d.dst, d.dir1Conn, d.dir2Conn)
	if d.workloadDiffInfo != "" {
		return diffLine + ", workloads-diff-info: " + d.workloadDiffInfo
	}
	return diffLine
}

// /////////////////////////
// diffFormatMD: implements the diffFormatter interface for md output format
type diffFormatMD struct {
}

var mdHeader = "| diff-type | source | destination | dir1 | dir2 | workloads-diff-info |\n" +
	"|-----------|--------|-------------|------|------|---------------------|"

// returns md string format of connections diff from connectivityDiff object
func (md *diffFormatMD) writeDiffOutput(connsDiff ConnectivityDiff) (string, error) {
	res := make([]string, 0)
	res = append(res, mdHeader)
	res = append(res, writeDiffLinesOrderedByCategory(connsDiff, md)...)
	return strings.Join(res, newLine), nil
}

func (md *diffFormatMD) singleDiffLine(d *singleDiffFields) string {
	return fmt.Sprintf("| %s | %s | %s | %s | %s | %s |",
		d.diffType, d.src, d.dst, d.dir1Conn, d.dir2Conn, d.workloadDiffInfo)
}

// /////////////////////////
// diffFormatCSV: implements the diffFormatter interface for csv output format
type diffFormatCSV struct {
}

var csvHeader = []string{"diff-type", "source", "destination", "dir1", "dir2", "workloads-diff-info"}

func (cs *diffFormatCSV) writeDiffOutput(connsDiff ConnectivityDiff) (string, error) {
	changesSortedByCategory := writeDiffLinesOrderedByCategory(connsDiff, cs)
	// writing csv rows into a buffer
	buf := new(bytes.Buffer)
	writer := csv.NewWriter(buf)
	if err := writer.Write(csvHeader); err != nil {
		return "", err
	}
	for _, diffData := range changesSortedByCategory {
		row := strings.Split(diffData, ";")
		if err := writer.Write(row); err != nil {
			return "", err
		}
	}
	writer.Flush()
	return buf.String(), nil
}

func (cs *diffFormatCSV) singleDiffLine(d *singleDiffFields) string {
	return fmt.Sprintf("%s;%s;%s;%s;%s;%s", d.diffType, d.src, d.dst, d.dir1Conn, d.dir2Conn, d.workloadDiffInfo)
}

// /////////////////////////
// diffFormatDOT: implements the diffFormatter interface for dot output format
type diffFormatDOT struct {
}

const (
	dotHeader  = "digraph {"
	dotClosing = "}"
)

func (df *diffFormatDOT) writeDiffOutput(connsDiff ConnectivityDiff) (string, error) {
	var edgeLines, peersLines, ingressAnalyzerEdges []string
	peersVisited := make(map[string]bool, 0) // set of peers
	// non changed
	ncPeers, nonChangedEdges, nonChangedIngressEdges := getEdgesAndPeersLinesByCategory(connsDiff.nonChangedConnections(), peersVisited)
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
	allLines := []string{dotHeader}
	allLines = append(allLines, peersLines...)
	allLines = append(allLines, edgeLines...)
	allLines = append(allLines, ingressAnalyzerEdges...)
	allLines = append(allLines, dotClosing)
	return strings.Join(allLines, newLine), nil
}

func getEdgesAndPeersLinesByCategory(connsPairs []*ConnsPair, peersSet map[string]bool) (pLines, cEdges, iEdges []string) {
	peersLines := make([]string, 0)
	connsEdges := make([]string, 0)
	ingressEdges := make([]string, 0)
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

func addEdgesLines(connsPair *ConnsPair) string {
	src, dst, _ := getConnPeersStrings(connsPair)
	firstConn, secondConn := getDirsConnsStrings(connsPair)
	switch connsPair.diffType {
	case nonChangedType:
		return getEdgeLine(src, dst, firstConn, nonChangedConnColor)
	case changedType:
		return getEdgeLine(src, dst, firstConn+"->"+secondConn, changedConnColor)
	case removedType:
		return getEdgeLine(src, dst, firstConn, removedConnColor)
	case addedType:
		return getEdgeLine(src, dst, secondConn, addedConnColor)
	default:
		return "" // should not get here
	}
}

func getEdgeLine(src, dst, connStr, edgeColor string) string {
	return fmt.Sprintf("\t%q -> %q [label=%q color=%q fontcolor=%q]", src, dst, connStr, edgeColor, edgeColor)
}

// kept empty for dot format, used to implement the diffFormatter interface in other formats
func (df *diffFormatDOT) singleDiffLine(d *singleDiffFields) string {
	return ""
}
