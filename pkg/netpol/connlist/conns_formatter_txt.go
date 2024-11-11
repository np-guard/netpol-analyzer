/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connlist

import (
	"fmt"
	"sort"
)

// formatText: implements the connsFormatter interface for txt output format
type formatText struct {
	ipMaps ipMaps
}

// writeOutput returns a textual string format of connections from list of Peer2PeerConnection objects,
// and exposure analysis results if exist
func (t *formatText) writeOutput(conns []Peer2PeerConnection, exposureConns []ExposedPeer, exposureFlag, explain bool) (string, error) {
	res := t.writeConnlistOutput(conns, exposureFlag, explain)
	if !exposureFlag {
		return res, nil
	}
	// else append exposure analysis results:
	if res != "" && res != newLineChar {
		res += newLineChar
	}
	res += t.writeExposureOutput(exposureConns)
	return res, nil
}

// writeConnlistOutput writes the section of the connlist result of the output
func (t *formatText) writeConnlistOutput(conns []Peer2PeerConnection, saveIPConns, explain bool) string {
	connLines := make([]singleConnFields, 0, len(conns))
	t.ipMaps = createIPMaps(saveIPConns)
	for i := range conns {
		if p2pConn := formSingleP2PConn(conns[i], explain); p2pConn.ConnString != "" {
			// ConnString might be empty if conns[i] does not contain 'InSet' ports
			connLines = append(connLines, p2pConn)
			// if we have exposure analysis results, also check if src/dst is an IP and store the connection
			if saveIPConns {
				t.ipMaps.saveConnsWithIPs(conns[i], explain)
			}
		}
	}
	sort.Slice(connLines, func(i, j int) bool {
		return (connLines[i].Src < connLines[j].Src ||
			(connLines[i].Src == connLines[j].Src && connLines[i].Dst < connLines[j].Dst) ||
			(connLines[i].Src == connLines[j].Src && connLines[i].Dst == connLines[j].Dst && connLines[i].ConnString < connLines[j].ConnString))
	})
	result := ""
	if explain {
		for _, p2pConn := range connLines {
			result += p2pConn.stringWithExplanation() + newLineChar
		}
	} else {
		for _, p2pConn := range connLines {
			result += p2pConn.string() + newLineChar
		}
	}
	return result
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
	ingressHead := ingressExposureHeader + newLineChar
	if len(egressExpLines) > 0 {
		// add empty line between the sections if both are not empty
		ingressHead = newLineChar + ingressHead
	}
	res += writeExposureSubSection(writeStrings(ingressExpLines, true, maxPeerStrLen), ingressHead)
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
