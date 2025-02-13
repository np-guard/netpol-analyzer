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

const (
	src             = "src"
	dst             = "dst"
	conn            = "conn"
	mdUnderLine     = "|-----|-----|------|"
	headerPrefix    = "## "
	subHeaderPrefix = "### "
	mdRowFormat     = "| %s | %s | %s |"
)

// getMDHeader formats the md output table header
func getMDHeader(srcFirst bool) string {
	tableHeaderForm := mdRowFormat + newLineChar + mdUnderLine
	if srcFirst {
		return fmt.Sprintf(tableHeaderForm, src, dst, conn)
	} // else dst first
	return fmt.Sprintf(tableHeaderForm, dst, src, conn)
}

// getMDLine formats a connection line for md output
func getMDLine(c singleConnFields, srcFirst bool) string {
	if srcFirst {
		return fmt.Sprintf(mdRowFormat, c.Src, c.Dst, c.ConnString)
	} // else dst first
	return fmt.Sprintf(mdRowFormat, c.Dst, c.Src, c.ConnString)
}

// writeOutput returns a md string form of connections from list of Peer2PeerConnection objects,
// and exposure analysis results from list ExposedPeer if exists
func (md *formatMD) writeOutput(conns []Peer2PeerConnection, exposureConns []ExposedPeer, exposureFlag, explain bool) (string, error) {
	explain = false // not supported
	// first write connlist lines
	allLines := md.writeMdConnlistLines(conns, exposureFlag, explain)
	if !exposureFlag {
		return strings.Join(allLines, newLineChar) + newLineChar, nil
	}
	// add exposure lines
	allLines = append(allLines, md.writeMdExposureLines(exposureConns)...)
	return strings.Join(allLines, newLineChar), nil
}

// writeMdLines returns sorted md lines from the sorted singleConnFields list
func writeMdLines(conns []singleConnFields, srcFirst bool) []string {
	res := make([]string, len(conns))
	for i := range conns {
		res[i] = getMDLine(conns[i], srcFirst)
	}
	return res
}

// writeMdConnlistLines returns md lines from the list of Peer2PeerConnection
func (md *formatMD) writeMdConnlistLines(conns []Peer2PeerConnection, saveIPConns, explain bool) []string {
	md.ipMaps = createIPMaps(saveIPConns)
	sortedConns := getConnlistAsSortedSingleConnFieldsArray(conns, md.ipMaps, saveIPConns, explain)
	connlistLines := []string{getMDHeader(true)} // connlist results are formatted: src | dst | conn
	connlistLines = append(connlistLines, writeMdLines(sortedConns, true)...)
	return connlistLines
}

// writeMdExposureLines returns md lines from exposure conns list
func (md *formatMD) writeMdExposureLines(exposureConns []ExposedPeer) []string {
	exposureMdLines := []string{headerPrefix + exposureAnalysisHeader}
	sortedIngExpConns, sortedEgExpConns, _ := getExposureConnsAsSortedSingleConnFieldsArray(exposureConns, md.ipMaps)
	// egress exposure formatted src | dst | conn
	// ingress exposure formatted: dst | src | conn
	exposureMdLines = append(exposureMdLines,
		writeExposureSubSection(writeMdLines(sortedEgExpConns, true), getMdSubSectionHeader(false)),
		writeExposureSubSection(writeMdLines(sortedIngExpConns, false), getMdSubSectionHeader(true)))
	return exposureMdLines
}

// getMdSubSectionHeader returns the headers of a new section in md result and its table's header
func getMdSubSectionHeader(isIngress bool) string {
	if isIngress {
		return subHeaderPrefix + ingressExposureHeader + newLineChar + getMDHeader(false) + newLineChar
	}
	return subHeaderPrefix + egressExposureHeader + newLineChar + getMDHeader(true) + newLineChar
}
