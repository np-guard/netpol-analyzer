package diff

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/connlist"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
)

// diffFormatter implements diff output formatting in the required output format
type diffFormatter interface {
	writeDiffOutput(connsDiff ConnectivityDiff) (string, error)
	singleDiffLine(d *singleDiffFields) string
}

const (
	noConns     = "No Connections"
	changedType = "changed"
	removedType = "removed"
	addedType   = "added"
	infoPrefix  = " (workload "
	infoSuffix  = ")"
	space       = " "
)

var newLine = fmt.Sprintln("")

type singleDiffFields struct {
	src      string
	dst      string
	dir1Conn string
	dir2Conn string
	diffType string
}

func formDiffFieldsDataOfChangedConns(changedConns []*ConnsPair) (netpolsChanged, ingressChanged []*singleDiffFields) {
	netpolsRes := make([]*singleDiffFields, 0) // changes in connections from netpols
	ingressRes := make([]*singleDiffFields, 0) // changes in connections from ingress-controller
	for _, pair := range changedConns {
		diffData := &singleDiffFields{
			src:      pair.firstConn.Src().String(),
			dst:      pair.firstConn.Dst().String(),
			dir1Conn: connlist.GetProtocolsAndPortsStr(pair.firstConn),
			dir2Conn: connlist.GetProtocolsAndPortsStr(pair.secondConn),
			diffType: changedType,
		}
		if eval.IsFakePeer(pair.firstConn.Src()) {
			ingressRes = append(ingressRes, diffData)
		} else {
			netpolsRes = append(netpolsRes, diffData)
		}
	}
	return netpolsRes, ingressRes
}

func formDiffFieldsDataOfRemovedConns(removedConns []RemovedConnsPeers) (netpolsRemoved, ingressRemoved []*singleDiffFields) {
	netpolsRes := make([]*singleDiffFields, 0) // connections removed based on netpols rules
	ingressRes := make([]*singleDiffFields, 0) // removed ingress connections
	for _, removedData := range removedConns {
		p2pConn := removedData.removedConn
		diffInfo := removedType
		if removedData.removedSrc {
			diffInfo += infoPrefix + p2pConn.Src().String() + space + removedType + infoSuffix
		}
		if removedData.removedDst {
			diffInfo += infoPrefix + p2pConn.Dst().String() + space + removedType + infoSuffix
		}
		diffData := &singleDiffFields{
			src:      p2pConn.Src().String(),
			dst:      p2pConn.Dst().String(),
			dir1Conn: connlist.GetProtocolsAndPortsStr(p2pConn),
			dir2Conn: noConns,
			diffType: diffInfo,
		}
		if eval.IsFakePeer(p2pConn.Src()) {
			ingressRes = append(ingressRes, diffData)
		} else {
			netpolsRes = append(netpolsRes, diffData)
		}
	}
	return netpolsRes, ingressRes
}

func formDiffFieldsDataOfAddedConns(addedConns []AddedConnsPeers) (netpolsAdded, ingressAdded []*singleDiffFields) {
	netpolsRes := make([]*singleDiffFields, 0) // added connections based on netpols rules
	ingressRes := make([]*singleDiffFields, 0) // added ingress connections
	for _, addedData := range addedConns {
		p2pConn := addedData.addedConn
		diffInfo := addedType
		if addedData.addedSrc {
			diffInfo += infoPrefix + p2pConn.Src().String() + space + addedType + infoSuffix
		}
		if addedData.addedDst {
			diffInfo += infoPrefix + p2pConn.Dst().String() + space + addedType + infoSuffix
		}
		diffData := &singleDiffFields{
			src:      p2pConn.Src().String(),
			dst:      p2pConn.Dst().String(),
			dir1Conn: noConns,
			dir2Conn: connlist.GetProtocolsAndPortsStr(p2pConn),
			diffType: diffInfo,
		}
		if eval.IsFakePeer(p2pConn.Src()) {
			ingressRes = append(ingressRes, diffData)
		} else {
			netpolsRes = append(netpolsRes, diffData)
		}
	}
	return netpolsRes, ingressRes
}

func writeDiffLinesOrderedByCategory(connsDiff ConnectivityDiff, df diffFormatter) []string {
	res := make([]string, 0)
	// changed lines
	netpolsChanged, ingressChanged := formDiffFieldsDataOfChangedConns(connsDiff.ChangedConnections())
	changedNetpolsLines := writeDiffLines(netpolsChanged, df)
	changedIngressLines := writeDiffLines(ingressChanged, df)
	// added lines
	netpolsAdded, ingressAdded := formDiffFieldsDataOfAddedConns(connsDiff.AddedConnections())
	addedNetpolsLines := writeDiffLines(netpolsAdded, df)
	addedIngressLines := writeDiffLines(ingressAdded, df)
	// removed lines
	netpolsRemoved, ingressRemoved := formDiffFieldsDataOfRemovedConns(connsDiff.RemovedConnections())
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
