/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connlist

import (
	"fmt"
	"strings"
)

// formatMD: implements the connsFormatter interface for md output format
type formatMD struct {
	ipMaps ipMaps
}

// getMDHeader formats the md output header
func getMDHeader() string {
	return "| src | dst | conn |\n|-----|-----|------|"
}

// getMDLine formats a connection line for md output
func getMDLine(c singleConnFields) string {
	return fmt.Sprintf("| %s | %s | %s |", c.Src, c.Dst, c.ConnString)
}

// writeOutput returns a md string form of connections from list of Peer2PeerConnection objects,
// and exposure analysis results from list ExposedPeer if exists
func (md *formatMD) writeOutput(conns []Peer2PeerConnection, exposureConns []ExposedPeer, exposureFlag bool) (string, error) {
	connlistMdLines := md.writeMdConnlistLines(conns, exposureFlag)
	allLines := []string{getMDHeader()}
	allLines = append(allLines, connlistMdLines...)

	if exposureFlag {
		allLines = append(allLines, "## "+exposureAnalysisHeader, getMDHeader())
		exposureMdLines := md.writeMdExposureLines(exposureConns)
		allLines = append(allLines, exposureMdLines...)
	}
	return strings.Join(allLines, newLineChar), nil
}

// writeMdLines returns sorted md lines from the sorted singleConnFields list
func writeMdLines(conns []singleConnFields) []string {
	res := make([]string, len(conns))
	for i := range conns {
		res[i] = getMDLine(conns[i])
	}
	return res
}

// writeMdConnlistLines returns md lines from the list of Peer2PeerConnection
func (md *formatMD) writeMdConnlistLines(conns []Peer2PeerConnection, saveIPConns bool) []string {
	md.ipMaps = createIPMaps(saveIPConns)
	sortedConns := getConnlistAsSortedSingleConnFieldsArray(conns, md.ipMaps, saveIPConns)
	return writeMdLines(sortedConns)
}

// writeMdExposureLines returns md lines from exposure conns list
func (md *formatMD) writeMdExposureLines(exposureConns []ExposedPeer) []string {
	sortedExposureConns := getExposureConnsAsSortedSingleConnFieldsArray(exposureConns, md.ipMaps)
	return writeMdLines(sortedExposureConns)
}
