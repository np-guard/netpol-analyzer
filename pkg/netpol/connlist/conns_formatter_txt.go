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
func (t *formatText) writeOutput(conns []Peer2PeerConnection, exposureConns []ExposedPeer, exposureFlag, explain bool,
	focusConnStr string) (string, error) {
	res := t.writeConnlistOutput(conns, exposureFlag, explain, focusConnStr)
	if !exposureFlag {
		return res, nil
	}
	// else append exposure analysis results:
	if res != "" && res != newLineChar {
		res += newLineChar
	}
	res += t.writeExposureOutput(exposureConns, focusConnStr)
	return res, nil
}

// writeConnlistOutput writes the section of the connlist result of the output
func (t *formatText) writeConnlistOutput(conns []Peer2PeerConnection, saveIPConns, explain bool, focusConnStr string) string {
	connLines := make([]singleConnFields, 0, len(conns))        // lines in the default pod networks
	connsByUDN := make(map[string][]singleConnFields)           // map from a udn to its conns
	defaultConnLines := make([]singleConnFields, 0, len(conns)) // used with explain
	t.ipMaps = createIPMaps(saveIPConns)
	for i := range conns {
		p2pConn, udn := formSingleP2PConn(conns[i], explain)
		if explain && conns[i].(*connection).onlyDefaultRule() {
			defaultConnLines = append(defaultConnLines, p2pConn)
		} else {
			if udn != "" { // append conn to its udn
				if _, ok := connsByUDN[udn]; !ok {
					connsByUDN[udn] = make([]singleConnFields, 0)
				}
				connsByUDN[udn] = append(connsByUDN[udn], p2pConn)
			} else { // append to the pod-network conns
				connLines = append(connLines, p2pConn)
			}
		}
		// if we have exposure analysis results, also check if src/dst is an IP and store the connection
		// save if there is a connection
		if saveIPConns && p2pConn.ConnString != "" {
			t.ipMaps.saveConnsWithIPs(conns[i], explain)
		}
	}
	result := ""
	sortedConnLines := sortConnFields(connLines, true)
	sortedDefaultConnLines := sortConnFields(defaultConnLines, true)
	if explain {
		result = writeSingleTypeLinesExplanationOutput(sortedConnLines, specificConnHeader, false) +
			writeSingleTypeLinesExplanationOutput(sortedDefaultConnLines, systemDefaultPairsHeader, true)
	} else { // not explain (regular connlist)
		if focusConnStr == "" { // write all pod network conns  (src => dst: conn)
			for _, p2pConn := range sortedConnLines {
				result += p2pConn.string() + newLineChar
			}
			result += writeUDNSections(connsByUDN, false)
		} else { // conns are already filtered by focus conn - print only (src => dst)
			result = writeFocusConnTxtOutput(sortedConnLines, connsByUDN, focusConnStr)
		}
	}
	return result
}

func writeUDNSections(connsByUDN map[string][]singleConnFields, nodePairForm bool) string {
	res := ""
	udnKeys := sortMapKeys(connsByUDN)
	for _, udn := range udnKeys {
		res += newLineChar + udn + colon + newLineChar
		sortedConns := sortConnFields(connsByUDN[udn], true)
		for i := range sortedConns {
			if nodePairForm {
				res += sortedConns[i].nodePairString() + newLineChar
			} else {
				res += sortedConns[i].string() + newLineChar
			}
		}
	}
	return res
}

func sortMapKeys(udnMap map[string][]singleConnFields) []string {
	keys := make([]string, 0, len(udnMap))
	for k := range udnMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
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
	onStr                    = " On "
)

// writeExposureOutput writes the section of the exposure-analysis result
func (t *formatText) writeExposureOutput(exposureResults []ExposedPeer, focusConnStr string) string {
	// getting the max peer String length (to be used for writing fixed indented lines)
	maxPeerStrLen := getMaxPeerStringLength(exposureResults)
	// results lines
	ingressExpLines, egressExpLines, unprotectedLines := getExposureConnsAsSortedSingleConnFieldsArray(exposureResults, t.ipMaps)
	sort.Strings(unprotectedLines)
	// writing results of exposure for all peers
	res := exposureAnalysisHeader
	if focusConnStr != "" {
		res += onStr + focusConnStr
	}
	res += colon + newLineChar
	res += writeExposureSubSection(writeStrings(egressExpLines, false, maxPeerStrLen, focusConnStr), egressExposureHeader+newLineChar)
	ingressHead := ingressExposureHeader + newLineChar
	if len(egressExpLines) > 0 {
		// add empty line between the sections if both are not empty
		ingressHead = newLineChar + ingressHead
	}
	res += writeExposureSubSection(writeStrings(ingressExpLines, true, maxPeerStrLen, focusConnStr), ingressHead)
	if focusConnStr == "" { // no need to add unprotected lines if results are for a focus conn
		res += writeExposureSubSection(unprotectedLines, unprotectedHeader)
	}
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
func writeStrings(xgressData []singleConnFields, isIngress bool, maxStrLen int, focusConnStr string) []string {
	res := make([]string, len(xgressData))
	for i := range xgressData {
		res[i] = xgressData[i].exposureString(isIngress, maxStrLen, focusConnStr)
	}
	return res
}

const (
	egressDir  = "=>"
	ingressDir = "<="
)

// exposureString writes the current singleConnFields in the format of exposure result line
func (c singleConnFields) exposureString(isIngress bool, maxStrLen int, focusConnStr string) string {
	formatStr := fmt.Sprintf("%%-%ds \t%%s \t%%s : %%s", maxStrLen)
	if focusConnStr != "" { // don't print conn if the results are focused on specific connection
		formatStr = fmt.Sprintf("%%-%ds \t%%s \t%%s", maxStrLen)
	}
	if isIngress {
		if focusConnStr != "" {
			return fmt.Sprintf(formatStr, c.Dst, ingressDir, c.Src)
		}
		return fmt.Sprintf(formatStr, c.Dst, ingressDir, c.Src, c.ConnString)
	} // egress
	if focusConnStr != "" {
		return fmt.Sprintf(formatStr, c.Src, egressDir, c.Dst)
	}
	return fmt.Sprintf(formatStr, c.Src, egressDir, c.Dst, c.ConnString)
}

const (
	colon = ":"
)

func writeFocusConnTxtOutput(sortedConnLines []singleConnFields, udnConns map[string][]singleConnFields, focusConnStr string) string {
	result := "Permitted connections on " + focusConnStr + colon + newLineChar
	for _, conn := range sortedConnLines {
		result += conn.nodePairString() + newLineChar
	}
	result += writeUDNSections(udnConns, true)
	return result
}
