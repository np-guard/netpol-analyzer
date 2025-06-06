/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connlist

import (
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// formatText: implements the connsFormatter interface for txt output format
type formatText struct {
	ipMaps ipMaps
}

// writeOutput returns a textual string format of connections from list of Peer2PeerConnection objects,
// and exposure analysis results if exist
func (t *formatText) writeOutput(conns []Peer2PeerConnection, exposureConns []ExposedPeer, exposureFlag, explain bool,
	focusConnStr string, primaryUdnNamespaces map[string]eval.UDNData) (string, error) {
	res := t.writeConnlistOutput(conns, exposureFlag, explain, focusConnStr, primaryUdnNamespaces)
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
func (t *formatText) writeConnlistOutput(conns []Peer2PeerConnection, saveIPConns, explain bool, focusConnStr string,
	primaryUdnNamespaces map[string]eval.UDNData) string {
	connLines := make([]singleConnFields, 0, len(conns))        // lines in the default pod networks
	connsByUDN := make(map[string][]singleConnFields)           // map from a primary udn to its conns
	connsByCUDN := make(map[string][]singleConnFields)          // map from a primary c-udn to its conns
	defaultConnLines := make([]singleConnFields, 0, len(conns)) // used with explain
	crossNetworksLinesFlag := false                             // indicates that there are denied conns because of isolated networks
	t.ipMaps = createIPMaps(saveIPConns)
	for i := range conns {
		p2pConn, udn, isClusterUdn := formSingleP2PConn(conns[i], explain, primaryUdnNamespaces)
		switch {
		case explain && conns[i].(*connection).onlyDefaultRule():
			defaultConnLines = append(defaultConnLines, p2pConn)
		case explain && conns[i].(*connection).deniedCrossNetworksRule():
			crossNetworksLinesFlag = true
		default:
			if udn != "" { // append allowed conn to its udn for output grouping
				if !isClusterUdn {
					addToUDNMap(udn, connsByUDN, p2pConn)
				} else {
					addToUDNMap(udn, connsByCUDN, p2pConn)
				}
			} else { // append to the pod-network conns
				connLines = append(connLines, p2pConn)
			}
		}
		// if we have exposure analysis results, also check if src/dst is an IP and store the connection
		// save if there is a connection
		if saveIPConns && p2pConn.ConnString != "" {
			t.ipMaps.saveConnsWithIPs(conns[i], explain, primaryUdnNamespaces)
		}
	}
	result := ""
	sortedConnLines := sortConnFields(connLines, true)
	sortedDefaultConnLines := sortConnFields(defaultConnLines, true)
	if explain {
		podNetworkHeader := specificConnHeader
		if len(connsByUDN) != 0 || len(connsByCUDN) != 0 {
			podNetworkHeader += " in pod-network"
		}
		result = writeSingleTypeLinesExplanationOutput(sortedConnLines, podNetworkHeader, false) +
			writeUDNSections(connsByUDN, false, true, udnStr) + writeUDNSections(connsByCUDN, false, true, cudnStr) +
			writeSingleTypeLinesExplanationOutput(sortedDefaultConnLines, systemDefaultPairsHeader, true) +
			writeSingleLineExplanationNote(crossNetworksLinesFlag)
	} else { // not explain (regular connlist)
		if focusConnStr == "" { // write all pod network conns  (src => dst: conn)
			result = writeFullConnlistTxtOutput(sortedConnLines, connsByUDN, connsByCUDN)
		} else { // conns are already filtered by focus conn - print only (src => dst)
			result = writeFocusConnTxtOutput(sortedConnLines, connsByUDN, connsByCUDN, focusConnStr)
		}
	}
	return result
}

func addToUDNMap(udn string, udnMap map[string][]singleConnFields, p2pConn singleConnFields) {
	if _, ok := udnMap[udn]; !ok {
		udnMap[udn] = make([]singleConnFields, 0)
	}
	udnMap[udn] = append(udnMap[udn], p2pConn)
}

// writeUDNSections writes the conns lines grouped per UDN/CUDN
func writeUDNSections(connsByUDN map[string][]singleConnFields, nodePairForm, explain bool, udnType string) string {
	res := ""
	udnKeys := sortMapKeys(connsByUDN)
	for _, udn := range udnKeys {
		sortedConns := sortConnFields(connsByUDN[udn], true)
		if explain {
			explainUDNHeader := specificConnHeader + " in " + udnType + udn
			res += writeSingleTypeLinesExplanationOutput(sortedConns, explainUDNHeader, false)
		} else { // not explain
			res += newLineChar + sectionHeaderPrefix + udnType + udn + colon + newLineChar
			for i := range sortedConns {
				if nodePairForm { // running with focus-conn
					res += sortedConns[i].nodePairString() + newLineChar
				} else { // regular connlist line (with conn)
					res += sortedConns[i].string() + newLineChar
				}
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
	crossNetworksDenyHeader  = "Denied cross-network connections"
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
	colon               = ":"
	sectionHeaderPrefix = "Permitted connectivity analyzed in "
	podNetworkStr       = "Pod network"
	cudnStr             = "CUDN "
	udnStr              = "UDN "
)

func writeFocusConnTxtOutput(sortedConnLines []singleConnFields, udnConns, cudnConns map[string][]singleConnFields,
	focusConnStr string) string {
	result := "Permitted connections on " + focusConnStr + colon + newLineChar
	for _, conn := range sortedConnLines {
		result += conn.nodePairString() + newLineChar
	}
	result += writeUDNSections(udnConns, true, false, udnStr) + writeUDNSections(cudnConns, true, false, cudnStr)
	return result
}

func writeFullConnlistTxtOutput(sortedConnLines []singleConnFields, udnConns, cudnConns map[string][]singleConnFields) string {
	result := ""
	if (len(udnConns) != 0 || len(cudnConns) != 0) && len(sortedConnLines) != 0 {
		result += sectionHeaderPrefix + podNetworkStr + colon + newLineChar
	}
	for _, p2pConn := range sortedConnLines {
		result += p2pConn.string() + newLineChar
	}
	result += writeUDNSections(udnConns, false, false, udnStr) + writeUDNSections(cudnConns, false, false, cudnStr)
	return result
}

func writeSingleLineExplanationNote(crossNetworksDeniedFlag bool) string {
	if !crossNetworksDeniedFlag {
		return ""
	}
	return newLineChar + "*** Note: Connections between any peers from separate isolated networks are denied by default " +
		"and therefore not listed in this report."
}
