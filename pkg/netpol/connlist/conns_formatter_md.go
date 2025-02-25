/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connlist

import (
	"fmt"
	"strings"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
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
func getMDHeader(srcFirst bool, focusConn *common.ConnectionSet) string {
	tableHeaderForm := mdRowFormat + newLineChar + mdUnderLine
	tableHeaderFormFocusConn := mdRowFormatFocusConn + newLineChar + mdUnderLineFocusConn
	if srcFirst {
		if focusConn != nil {
			return fmt.Sprintf(tableHeaderFormFocusConn, src, dst)
		}
		return fmt.Sprintf(tableHeaderForm, src, dst, conn)
	} // else dst first
	if focusConn != nil {
		return fmt.Sprintf(tableHeaderFormFocusConn, dst, src)
	}
	return fmt.Sprintf(tableHeaderForm, dst, src, conn)
}

// getMDLine formats a connection line for md output
func getMDLine(c singleConnFields, srcFirst bool, focusConn *common.ConnectionSet) string {
	if srcFirst {
		if focusConn != nil {
			return fmt.Sprintf(mdRowFormatFocusConn, c.Src, c.Dst)
		}
		return fmt.Sprintf(mdRowFormat, c.Src, c.Dst, c.ConnString)
	} // else dst first
	if focusConn != nil {
		return fmt.Sprintf(mdRowFormatFocusConn, c.Dst, c.Src)
	}
	return fmt.Sprintf(mdRowFormat, c.Dst, c.Src, c.ConnString)
}

// writeOutput returns a md string form of connections from list of Peer2PeerConnection objects,
// and exposure analysis results from list ExposedPeer if exists
// explain input is ignored since not supported with this format
func (md *formatMD) writeOutput(conns []Peer2PeerConnection, exposureConns []ExposedPeer, exposureFlag, explain bool,
	focusConn *common.ConnectionSet) (string, error) {
	// first write connlist lines
	allLines := md.writeMdConnlistLines(conns, exposureFlag, false, focusConn)
	if !exposureFlag {
		return strings.Join(allLines, newLineChar) + newLineChar, nil
	}
	// add exposure lines
	allLines = append(allLines, md.writeMdExposureLines(exposureConns, focusConn)...)
	return strings.Join(allLines, newLineChar), nil
}

// writeMdLines returns sorted md lines from the sorted singleConnFields list
func writeMdLines(conns []singleConnFields, srcFirst bool, focusConn *common.ConnectionSet) []string {
	res := make([]string, len(conns))
	for i := range conns {
		res[i] = getMDLine(conns[i], srcFirst, focusConn)
	}
	return res
}

// writeMdConnlistLines returns md lines from the list of Peer2PeerConnection
func (md *formatMD) writeMdConnlistLines(conns []Peer2PeerConnection, saveIPConns, explain bool, focusConn *common.ConnectionSet) []string {
	md.ipMaps = createIPMaps(saveIPConns)
	sortedConns := getConnlistAsSortedSingleConnFieldsArray(conns, md.ipMaps, saveIPConns, explain)
	connlistLines := []string{getMDHeader(true, focusConn)} // connlist results are formatted: src | dst | conn
	connlistLines = append(connlistLines, writeMdLines(sortedConns, true, focusConn)...)
	return connlistLines
}

// writeMdExposureLines returns md lines from exposure conns list
func (md *formatMD) writeMdExposureLines(exposureConns []ExposedPeer, focusConn *common.ConnectionSet) []string {
	expHeader := exposureAnalysisHeader
	if focusConn != nil {
		expHeader += onStr + focusConn.String()
	}
	expHeader += colon
	exposureMdLines := []string{headerPrefix + expHeader}
	sortedIngExpConns, sortedEgExpConns, _ := getExposureConnsAsSortedSingleConnFieldsArray(exposureConns, md.ipMaps)
	// egress exposure formatted src | dst | conn
	// ingress exposure formatted: dst | src | conn
	exposureMdLines = append(exposureMdLines,
		writeExposureSubSection(writeMdLines(sortedEgExpConns, true, focusConn), getMdSubSectionHeader(false, focusConn)),
		writeExposureSubSection(writeMdLines(sortedIngExpConns, false, focusConn), getMdSubSectionHeader(true, focusConn)))
	return exposureMdLines
}

// getMdSubSectionHeader returns the headers of a new section in md result and its table's header
func getMdSubSectionHeader(isIngress bool, focusConn *common.ConnectionSet) string {
	if isIngress {
		return subHeaderPrefix + ingressExposureHeader + newLineChar + getMDHeader(false, focusConn) + newLineChar
	}
	return subHeaderPrefix + egressExposureHeader + newLineChar + getMDHeader(true, focusConn) + newLineChar
}
