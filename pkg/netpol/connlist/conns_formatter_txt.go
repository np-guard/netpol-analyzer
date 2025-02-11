/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connlist

import (
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
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
	defaultConnLines := make([]singleConnFields, 0, len(conns))
	t.ipMaps = createIPMaps(saveIPConns)
	for i := range conns {
		p2pConn := formSingleP2PConn(conns[i], explain)
		if explain && conns[i].(*connection).OnlyDefaultRule() {
			defaultConnLines = append(defaultConnLines, p2pConn)
		} else {
			connLines = append(connLines, p2pConn)
		}
		// if we have exposure analysis results, also check if src/dst is an IP and store the connection
		if saveIPConns {
			t.ipMaps.saveConnsWithIPs(conns[i], explain)
		}
	}
	result := ""
	if explain {
		sortConnFields(connLines, true)
		sortConnFields(defaultConnLines, true)
		result = writeSingleTypeLinesExplanationOutput(connLines, specificConnHeader, false) +
			writeSingleTypeLinesExplanationOutput(defaultConnLines, systemDefaultPairsHeader, true)
	} else {
		sortConnFields(connLines, true)
		for _, p2pConn := range connLines {
			result += p2pConn.string() + newLineChar
		}
	}
	return result
}

func writeSingleTypeLinesExplanationOutput(lines []singleConnFields, header string, pairsOnly bool) string {
	if len(lines) == 0 {
		return ""
	}
	result := writeGroupHeader(header)
	for _, p2pConn := range lines {
		if pairsOnly {
			result += p2pConn.nodePairString() + newLineChar
		} else {
			result += nodePairSeparationLine
			result += p2pConn.stringWithExplanation()
		}
	}
	return result
}

const headerSep = "#"

func writeGroupHeader(header string) string {
	headerLine := headerSep + common.SpaceSeparator + header + common.SpaceSeparator + headerSep
	result := newLineChar + strings.Repeat(headerSep, len(headerLine)) + newLineChar
	result += headerLine
	result += newLineChar + strings.Repeat(headerSep, len(headerLine)) + newLineChar
	return result
}

const (
	unprotectedHeader        = "\nWorkloads not protected by network policies:\n"
	separationLine80         = "--------------------------------------------------------------------------------"
	nodePairSeparationLine   = separationLine80 + separationLine80 + common.NewLine
	systemDefaultPairsHeader = common.AllConnsStr + common.SpaceSeparator + common.ExplSystemDefault
	specificConnHeader       = "Specific connections and their reasons"
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
