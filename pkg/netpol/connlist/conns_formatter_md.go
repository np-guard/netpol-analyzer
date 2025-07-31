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
	src                  = "src"
	dst                  = "dst"
	conn                 = "conn"
	mdUnderLine          = "|-----|-----|------|"
	mdUnderLineFocusConn = "|-----|-----|"
	headerPrefix         = "## "
	subHeaderPrefix      = "### "
	mdRowFormat          = "| %s | %s | %s |"
	mdRowFormatFocusConn = "| %s | %s |"
)

// getMDHeader formats the md output table header
func getMDHeader(srcFirst bool, focusConnStr string) string {
	tableHeaderForm := mdRowFormat + newLineChar + mdUnderLine
	tableHeaderFormFocusConn := mdRowFormatFocusConn + newLineChar + mdUnderLineFocusConn
	if srcFirst {
		if focusConnStr != "" {
			return fmt.Sprintf(tableHeaderFormFocusConn, src, dst)
		}
		return fmt.Sprintf(tableHeaderForm, src, dst, conn)
	} // else dst first
	if focusConnStr != "" {
		return fmt.Sprintf(tableHeaderFormFocusConn, dst, src)
	}
	return fmt.Sprintf(tableHeaderForm, dst, src, conn)
}

// getMDLine formats a connection line for md output
func getMDLine(c *singleConnFields, srcFirst bool, focusConnStr string) string {
	if srcFirst {
		if focusConnStr != "" {
			return fmt.Sprintf(mdRowFormatFocusConn, c.Src, c.Dst)
		}
		return fmt.Sprintf(mdRowFormat, c.Src, c.Dst, c.ConnString)
	} // else dst first
	if focusConnStr != "" {
		return fmt.Sprintf(mdRowFormatFocusConn, c.Dst, c.Src)
	}
	return fmt.Sprintf(mdRowFormat, c.Dst, c.Src, c.ConnString)
}

// writeOutput returns a md string form of connections from list of Peer2PeerConnection objects,
// and exposure analysis results from list ExposedPeer if exists
// explain input is ignored since not supported with this format
func (md *formatMD) writeOutput(conns []Peer2PeerConnection, exposureConns []ExposedPeer, exposureFlag, explain bool,
	focusConnStr string) (string, error) {
	// first write connlist lines
	allLines := md.writeMdConnlistLines(conns, exposureFlag, false, focusConnStr)
	if !exposureFlag {
		return strings.Join(allLines, newLineChar) + newLineChar, nil
	}
	// add exposure lines
	allLines = append(allLines, md.writeMdExposureLines(exposureConns, focusConnStr)...)
	return strings.Join(allLines, newLineChar), nil
}

// writeMdLines returns sorted md lines from the sorted singleConnFields list
func writeMdLines(conns []*singleConnFields, srcFirst bool, focusConnStr string) []string {
	res := make([]string, len(conns))
	for i := range conns {
		res[i] = getMDLine(conns[i], srcFirst, focusConnStr)
	}
	return res
}

// writeMdConnlistLines returns md lines from the list of Peer2PeerConnection
func (md *formatMD) writeMdConnlistLines(conns []Peer2PeerConnection, saveIPConns, explain bool, focusConnStr string) []string {
	md.ipMaps = createIPMaps(saveIPConns)
	sortedConns := getConnlistAsSortedSingleConnFieldsArray(conns, md.ipMaps, saveIPConns, explain)
	connlistLines := []string{getMDHeader(true, focusConnStr)} // connlist results are formatted: src | dst | conn
	connlistLines = append(connlistLines, writeMdLines(sortedConns, true, focusConnStr)...)
	return connlistLines
}

// writeMdExposureLines returns md lines from exposure conns list
func (md *formatMD) writeMdExposureLines(exposureConns []ExposedPeer, focusConnStr string) []string {
	expHeader := exposureAnalysisHeader
	if focusConnStr != "" {
		expHeader += onStr + focusConnStr
	}
	expHeader += colon
	exposureMdLines := []string{headerPrefix + expHeader}
	sortedIngExpConns, sortedEgExpConns, _ := getExposureConnsAsSortedSingleConnFieldsArray(exposureConns, md.ipMaps)
	// egress exposure formatted src | dst | conn
	// ingress exposure formatted: dst | src | conn
	exposureMdLines = append(exposureMdLines,
		writeExposureSubSection(writeMdLines(sortedEgExpConns, true, focusConnStr), getMdSubSectionHeader(false, focusConnStr)),
		writeExposureSubSection(writeMdLines(sortedIngExpConns, false, focusConnStr), getMdSubSectionHeader(true, focusConnStr)))
	return exposureMdLines
}

// getMdSubSectionHeader returns the headers of a new section in md result and its table's header
func getMdSubSectionHeader(isIngress bool, focusConnStr string) string {
	if isIngress {
		return subHeaderPrefix + ingressExposureHeader + newLineChar + getMDHeader(false, focusConnStr) + newLineChar
	}
	return subHeaderPrefix + egressExposureHeader + newLineChar + getMDHeader(true, focusConnStr) + newLineChar
}
