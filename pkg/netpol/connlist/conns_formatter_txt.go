/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connlist

import (
	"fmt"
	"sort"
	"strings"
)

// formatText: implements the connsFormatter interface for txt output format
type formatText struct {
	ipMaps ipMaps
}

// writeOutput returns a textual string format of connections from list of Peer2PeerConnection objects,
// and exposure analysis results if exist
func (t *formatText) writeOutput(conns []Peer2PeerConnection, exposureConns []ExposedPeer, exposureFlag bool) (string, error) {
	res := t.writeConnlistOutput(conns, exposureFlag)
	if !exposureFlag {
		return res, nil
	}
	// else append exposure analysis results:
	if res != "" {
		res += newLineChar
	}
	res += t.writeExposureOutput(exposureConns)
	return res, nil
}

// writeConnlistOutput writes the section of the connlist result of the output
func (t *formatText) writeConnlistOutput(conns []Peer2PeerConnection, saveIPConns bool) string {
	connLines := make([]string, len(conns))
	t.ipMaps = createIPMaps(saveIPConns)
	for i := range conns {
		connLines[i] = formSingleP2PConn(conns[i]).string()
		// if we have exposure analysis results, also check if src/dst is an IP and store the connection
		if saveIPConns {
			t.ipMaps.saveConnsWithIPs(conns[i])
		}
	}
	sort.Strings(connLines)
	return strings.Join(connLines, newLineChar) + newLineChar
}

const (
	unprotectedHeader = "\nWorkloads not protected by network policies:\n"
)

// writeExposureOutput writes the section of the exposure-analysis result
func (t *formatText) writeExposureOutput(exposureResults []ExposedPeer) string {
	// getting the max peer String length (to be used for writing fixed indented lines)
	maxPeerStrLen := getMaxPeerStringLength(exposureResults)
	// results lines
	ingressExpLines, egressExpLines, unprotectedLines := getExposureConnsAsSortedSingleConnFieldsArray(exposureResults, t.ipMaps)
	sort.Strings(unprotectedLines)
	// writing results of exposure for all peers
	res := exposureAnalysisHeader + newLineChar
	res += writeExposureSubSection(writeStrings(egressExpLines, false, maxPeerStrLen), egressExposureHeader+newLineChar)
	res += writeExposureSubSection(writeStrings(ingressExpLines, true, maxPeerStrLen), ingressExposureHeader+newLineChar)
	res += writeExposureSubSection(unprotectedLines, unprotectedHeader)
	return res
}

// getMaxPeerStringLength returns the length of the longest peer string in the given exposed peers slice
func getMaxPeerStringLength(exposedPeers []ExposedPeer) (maxPeerStrLen int) {
	for i := range exposedPeers {
		maxPeerStrLen = max(maxPeerStrLen, len(exposedPeers[i].ExposedPeer().String()))
	}
	return maxPeerStrLen
}

// writeStrings writes the exposure conns as string lines list matching txt output format
func writeStrings(xgressData []singleConnFields, isIngress bool, maxStrLen int) []string {
	res := make([]string, len(xgressData))
	for i := range xgressData {
		res[i] = xgressData[i].exposureString(isIngress, maxStrLen)
	}
	return res
}

// exposureString writes the current singleConnFields in the format of exposure result line
func (c singleConnFields) exposureString(isIngress bool, maxStrLen int) string {
	formatStr := fmt.Sprintf("%%-%ds \t%%s \t%%s : %%s", maxStrLen)
	if isIngress {
		return fmt.Sprintf(formatStr, c.Dst, "<=", c.Src, c.ConnString)
	}
	return fmt.Sprintf(formatStr, c.Src, "=>", c.Dst, c.ConnString)
}
