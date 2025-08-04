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
	multipleNetworksEnabled bool
	workloadToNetworksMap   map[string][]string
	podNetworkWlsNum        int
	ipMaps                  ipMaps
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
//
//gocyclo:ignore
func (t *formatText) writeConnlistOutput(conns []Peer2PeerConnection, saveIPConns, explain bool, focusConnStr string) string {
	connLines := make([]*singleConnFields, 0, len(conns))        // lines in the default pod networks
	connsByUDN := make(map[string][]*singleConnFields)           // map from a primary udn to its conns
	connsByCUDN := make(map[string][]*singleConnFields)          // map from a primary c-udn to its conns
	connsByNAD := make(map[string][]*singleConnFields)           // map from a secondary network name to its conns
	defaultConnLines := make([]*singleConnFields, 0, len(conns)) // used with explain
	crossNetworksLinesFlag := false                              // indicates that there are denied conns because of isolated networks
	t.ipMaps = createIPMaps(saveIPConns)
	for i := range conns {
		p2pConn, isClusterUdn, networkInf := formSingleP2PConn(conns[i], explain)
		switch {
		case explain && conns[i].(*connection).onlyDefaultRule():
			defaultConnLines = append(defaultConnLines, p2pConn)
		case explain && conns[i].(*connection).deniedCrossNetworksRule():
			crossNetworksLinesFlag = true
		case networkInf == common.Primary: // append allowed conn to its udn/cudn for output grouping
			if !isClusterUdn {
				addToNetworkMap(connsByUDN, p2pConn)
			} else {
				addToNetworkMap(connsByCUDN, p2pConn)
			}
		case networkInf == common.Secondary: // append allowed conn to its nad for output grouping
			addToNetworkMap(connsByNAD, p2pConn)
		default: // append to the pod-network conns
			connLines = append(connLines, p2pConn)
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
		podNetworkHeader := specificConnHeader
		if len(connsByUDN) != 0 || len(connsByCUDN) != 0 || len(connsByNAD) != 0 {
			podNetworkHeader += " in pod-network" // add this header if there are also other networks in the cluster
		}
		result = writeSingleTypeLinesExplanationOutput(sortedConnLines, podNetworkHeader, false, t.multipleNetworksEnabled) +
			writeNetworksSection(connsByUDN, false, true, primaryUDN) +
			writeNetworksSection(connsByCUDN, false, true, primaryCUDN) +
			writeNetworksSection(connsByNAD, false, true, secondaryNAD) +
			writeSingleTypeLinesExplanationOutput(sortedDefaultConnLines, systemDefaultPairsHeader, true, t.multipleNetworksEnabled) +
			writeSingleLineExplanationNote(crossNetworksLinesFlag)
	} else { // not explain (regular connlist)
		if focusConnStr == "" { // write all pod network conns  (src => dst: conn)
			result = t.writeFullConnlistTxtOutput(sortedConnLines, connsByUDN, connsByCUDN, connsByNAD)
			if t.multipleNetworksEnabled && len(t.workloadToNetworksMap) != 0 {
				result += t.writeWorkloadToNetworksSection()
			}
		} else { // conns are already filtered by focus conn - print only (src => dst)
			result = writeFocusConnTxtOutput(sortedConnLines, connsByUDN, connsByCUDN, connsByNAD, focusConnStr)
		}
	}
	return result
}

func addToNetworkMap(networkMap map[string][]*singleConnFields, p2pConn *singleConnFields) {
	networkName := p2pConn.networkName
	if _, ok := networkMap[networkName]; !ok {
		networkMap[networkName] = make([]*singleConnFields, 0)
	}
	networkMap[networkName] = append(networkMap[networkName], p2pConn)
}

// writeNetworksSection writes the conns lines grouped per UDN/CUDN/NAD
func writeNetworksSection(connsByNetworkName map[string][]*singleConnFields, nodePairForm, explain bool, networkType string) string {
	res := ""
	networkKeys := sortMapKeys(connsByNetworkName)
	for _, network := range networkKeys {
		sortedConns := sortConnFields(connsByNetworkName[network], true)
		if explain {
			explainNetworkHeader := specificConnHeader + " in " + networkType + spaceSeparator + network
			res += writeSingleTypeLinesExplanationOutput(sortedConns, explainNetworkHeader, false, false)
		} else { // not explain
			res += newLineChar + sectionHeaderPrefix + networkType + spaceSeparator + network + colon + newLineChar
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

func sortMapKeys(networkMap map[string][]*singleConnFields) []string {
	keys := make([]string, 0, len(networkMap))
	for k := range networkMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func writeSingleTypeLinesExplanationOutput(lines []*singleConnFields, header string, pairsOnly,
	multipleNetworksEnabled bool) string {
	if len(lines) == 0 {
		return ""
	}
	result := writeGroupHeader(header)
	for _, p2pConn := range lines {
		if pairsOnly {
			result += p2pConn.nodePairString()
			if multipleNetworksEnabled {
				result += inNetStr + p2pConn.networkName + closing
			}
			result += newLineChar
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
	inNetStr                 = "    (in network: "
	closing                  = ")"
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
func writeStrings(xgressData []*singleConnFields, isIngress bool, maxStrLen int, focusConnStr string) []string {
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
func (c *singleConnFields) exposureString(isIngress bool, maxStrLen int, focusConnStr string) string {
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
	colon                       = ":"
	sectionHeaderPrefix         = "Permitted connectivity analyzed in "
	podNetworkStr               = "Pod network"
	spaceSeparator              = " "
	secondary                   = "secondary"
	primary                     = "primary"
	udnStr                      = "UDN"
	cudnStr                     = "CUDN"
	nadStr                      = "NAD"
	secondaryNAD                = secondary + spaceSeparator + nadStr
	primaryCUDN                 = primary + spaceSeparator + cudnStr
	primaryUDN                  = primary + spaceSeparator + udnStr
	emptyPodNetworkNoPods       = "all input workloads are configured with (C)UDN as their primary network interface"
	emptyPodNetworkBlockedConns = "All connections are not allowed for the workloads in the pod-network"
)

func writeFocusConnTxtOutput(sortedConnLines []*singleConnFields, udnConns, cudnConns, nadConns map[string][]*singleConnFields,
	focusConnStr string) string {
	result := "Permitted connections on " + focusConnStr + colon + newLineChar
	if (len(udnConns) != 0 || len(cudnConns) != 0 || len(nadConns) != 0) && len(sortedConnLines) != 0 {
		result += sectionHeaderPrefix + podNetworkStr + colon + newLineChar
	}
	for _, conn := range sortedConnLines {
		result += conn.nodePairString() + newLineChar
	}
	result += writeNetworksSection(udnConns, true, false, primaryUDN) +
		writeNetworksSection(cudnConns, true, false, primaryCUDN) +
		writeNetworksSection(nadConns, true, false, secondaryNAD)
	return result
}

func (t *formatText) writeFullConnlistTxtOutput(sortedConnLines []*singleConnFields, udnConns, cudnConns,
	nadConns map[string][]*singleConnFields) string {
	result := ""
	if len(udnConns) != 0 || len(cudnConns) != 0 || len(nadConns) != 0 {
		result += sectionHeaderPrefix + podNetworkStr + colon + newLineChar
		if len(sortedConnLines) == 0 && t.multipleNetworksEnabled {
			if t.podNetworkWlsNum == 0 {
				result += emptyPodNetworkNoPods + newLineChar
			} else {
				result += emptyPodNetworkBlockedConns + newLineChar
			}
		}
	}
	for _, p2pConn := range sortedConnLines {
		result += p2pConn.string() + newLineChar
	}
	result += writeNetworksSection(udnConns, false, false, primaryUDN) +
		writeNetworksSection(cudnConns, false, false, primaryCUDN) +
		writeNetworksSection(nadConns, false, false, secondaryNAD)
	return result
}

func writeSingleLineExplanationNote(crossNetworksDeniedFlag bool) string {
	if !crossNetworksDeniedFlag {
		return ""
	}
	return newLineChar + "*** Note: Connections between any peers from separate isolated networks are denied by default " +
		"and therefore not listed in this report."
}

func (t *formatText) writeWorkloadToNetworksSection() string {
	res := newLineChar + "Workload-to-Networks Mapping:" + newLineChar
	for _, wl := range t.sortWorkloadNetworksMapKeys() {
		sort.Strings(t.workloadToNetworksMap[wl][1:])
		res += wl + ": " + strings.Join(t.workloadToNetworksMap[wl], comma) + newLineChar
	}
	return res
}

func (t *formatText) sortWorkloadNetworksMapKeys() []string {
	keys := make([]string, 0, len(t.workloadToNetworksMap))
	for k := range t.workloadToNetworksMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
