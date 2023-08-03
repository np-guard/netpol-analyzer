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
	infoPrefix = " (workload "
	infoSuffix = ")"
	space      = " "
	and        = " and "
)

var newLine = fmt.Sprintln("")

type singleDiffFields struct {
	src      string
	dst      string
	dir1Conn string
	dir2Conn string
	diffType string
}

func formDiffFieldsDataOfDiffConns(diffConns []*ConnsPair) (netpolsDiff, ingressDiff []*singleDiffFields) {
	netpolsRes := make([]*singleDiffFields, 0) // diff in connections from netpols
	ingressRes := make([]*singleDiffFields, 0) // diff in connections from ingress-controller
	for _, d := range diffConns {
		firstDirConn, secondDirConn := getDirsConnsStrings(d)
		srcStr, dstStr, isSrcIngress := getConnPeersStrings(d)
		diffData := &singleDiffFields{
			src:      srcStr,
			dst:      dstStr,
			dir1Conn: firstDirConn,
			dir2Conn: secondDirConn,
			diffType: getDiffInfo(d),
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
	case changedType, removedType:
		return c.firstConn.Src().String(), c.firstConn.Dst().String(), c.firstConn.Src().IsFakePeer()
	case addedType:
		return c.secondConn.Src().String(), c.secondConn.Dst().String(), c.secondConn.Src().IsFakePeer()
	default:
		return "", "", false // should not get here
	}
}
func getDirsConnsStrings(c *ConnsPair) (dir1Str, dir2Str string) {
	switch c.diffType {
	case changedType:
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
	if c.diffType == changedType {
		return changedType
	}
	srcStr, dstStr, _ := getConnPeersStrings(c)
	// handling added or removed diff data
	diffInfo := c.diffType
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
		diffInfo += space + c.diffType + infoSuffix
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
	return fmt.Sprintf("source: %s, destination: %s, dir1:  %s, dir2: %s, diff-type: %s",
		d.src, d.dst, d.dir1Conn, d.dir2Conn, d.diffType)
}

// /////////////////////////
// diffFormatMD: implements the diffFormatter interface for md output format
type diffFormatMD struct {
}

var mdHeader = "| source | destination | dir1 | dir2 | diff-type |\n|--------|-------------|------|------|-----------|"

// returns md string format of connections diff from connectivityDiff object
func (md *diffFormatMD) writeDiffOutput(connsDiff ConnectivityDiff) (string, error) {
	res := make([]string, 0)
	res = append(res, mdHeader)
	res = append(res, writeDiffLinesOrderedByCategory(connsDiff, md)...)
	return strings.Join(res, newLine), nil
}

func (md *diffFormatMD) singleDiffLine(d *singleDiffFields) string {
	return fmt.Sprintf("| %s | %s | %s | %s | %s |",
		d.src, d.dst, d.dir1Conn, d.dir2Conn, d.diffType)
}

// /////////////////////////
// diffFormatCSV: implements the diffFormatter interface for csv output format
type diffFormatCSV struct {
}

var csvHeader = []string{"source", "destination", "dir1", "dir2", "diff-type"}

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
	return fmt.Sprintf("%s;%s;%s;%s;%s", d.src, d.dst, d.dir1Conn, d.dir2Conn, d.diffType)
}
