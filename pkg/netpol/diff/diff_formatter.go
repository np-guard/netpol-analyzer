package diff

import (
	"fmt"
	"sort"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/connlist"
)

// diffFormatter implements diff output formatting in the required output format
type diffFormatter interface {
	writeDiffOutput(connsDiff ConnectivityDiff) (string, error) // writes the diff output in the required format
	singleDiffLine(d *singleDiffFields) string                  // forms a single diff line in the required format
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

// formDiffFieldsDataOfDiffConns for each conn pair, forms the required fields of diff data.
// getting array of ConnsPair , returning an array of singleDiffFields
// splits the result into two arrays, one for policy conns the other ingress conns
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

// getConnPeersStrings returns the string form of the peers names, src and dst for the given conns pair,
// and an indication if the src is an ingress-controller
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

// getDirsConnsStrings returns the string forms of the connections in a single diff connsPair
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

// getDiffInfo computes the diff description string (if to include added/removed workloads)
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

// writeDiffLinesOrderedByCategory returns a list of diff lines ordered by categories : changed, added, removed.
// relevant ingress-controller connections are at the end of each category
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

// writeDiffLines returns the diff lines formed in the required format
func writeDiffLines(diffData []*singleDiffFields, df diffFormatter) []string {
	res := make([]string, len(diffData))
	for i, singleDiffData := range diffData {
		res[i] = df.singleDiffLine(singleDiffData)
	}
	sort.Strings(res)
	return res
}
