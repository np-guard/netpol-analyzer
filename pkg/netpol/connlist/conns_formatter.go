/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connlist

import (
	"fmt"
	"sort"
	"strings"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

var newLineChar = fmt.Sprintln("")

// ipMaps is a struct for saving connections with ip-blocks from connlist
// connections with IP-peers should appear in both connlist and exposure-analysis output sections
// used in txt , md, csv , json formats
type ipMaps struct {
	// PeerToConnsFromIPs map from real peer.String() to its ingress connections from ip-blocks
	// extracted from the []Peer2PeerConnection conns to be appended also to the exposure-analysis output
	// i.e : if connlist output contains `0.0.0.0-255.255.255.255 => ns1/workload-a : All Connections`
	// the PeerToConnsFromIPs will contain following entry: (to be written also in exposure output)
	// {ns1/workload-a: []singleConnFields{{src: 0.0.0.0-255.255.255.255, dst: ns1/workload-a, conn: All Connections},}}
	PeerToConnsFromIPs map[string][]singleConnFields

	// peerToConnsToIPs map from real peer.String() to its egress connections to ip-blocks
	// extracted from the []Peer2PeerConnection conns to be appended also to the exposure-analysis output
	peerToConnsToIPs map[string][]singleConnFields
}

// saveConnsWithIPs gets a P2P connection; if the connection includes an IP-Peer as one of its end-points; the conn is saved in the
// matching map of the formatText maps
func (i *ipMaps) saveConnsWithIPs(conn Peer2PeerConnection, explain bool) {
	if conn.Src().IsPeerIPType() && !isEmpty(conn) {
		i.PeerToConnsFromIPs[conn.Dst().String()] = append(i.PeerToConnsFromIPs[conn.Dst().String()], formSingleP2PConn(conn, explain))
	}
	if conn.Dst().IsPeerIPType() && !isEmpty(conn) {
		i.peerToConnsToIPs[conn.Src().String()] = append(i.peerToConnsToIPs[conn.Src().String()], formSingleP2PConn(conn, explain))
	}
}

func isEmpty(conn Peer2PeerConnection) bool {
	return !conn.AllProtocolsAndPorts() && len(conn.ProtocolsAndPorts()) == 0
}

// createIPMaps returns an ipMaps object with empty maps if required
func createIPMaps(initMapsFlag bool) (ipMaps ipMaps) {
	if initMapsFlag {
		ipMaps.peerToConnsToIPs = make(map[string][]singleConnFields)
		ipMaps.PeerToConnsFromIPs = make(map[string][]singleConnFields)
	}
	return ipMaps
}

// connsFormatter implements output formatting in the required output format
type connsFormatter interface {
	writeOutput(conns []Peer2PeerConnection, exposureConns []ExposedPeer, exposureFlag bool, explain bool) (string, error)
}

// singleConnFields represents a single connection object
type singleConnFields struct {
	Src         string `json:"src"`
	Dst         string `json:"dst"`
	ConnString  string `json:"conn"`
	explanation string
}

// string representation of the singleConnFields struct
func (c singleConnFields) string() string {
	return fmt.Sprintf("%s => %s : %s", c.Src, c.Dst, c.ConnString)
}

func (c singleConnFields) nodePairString() string {
	return fmt.Sprintf("%s => %s", c.Src, c.Dst)
}

func (c singleConnFields) stringWithExplanation() string {
	return fmt.Sprintf("Connections between %s => %s:\n\n%s", c.Src, c.Dst, c.explanation)
}

// formSingleP2PConn returns a string representation of single connection fields as singleConnFields object
func formSingleP2PConn(conn Peer2PeerConnection, explain bool) singleConnFields {
	connStr := common.ConnStrFromConnProperties(conn.AllProtocolsAndPorts(), conn.ProtocolsAndPorts())
	expl := ""
	if explain {
		expl = common.ExplanationFromConnProperties(conn.AllProtocolsAndPorts(), conn.(*connection).commonImplyingRules, conn.ProtocolsAndPorts())
	}
	return singleConnFields{Src: conn.Src().String(), Dst: conn.Dst().String(), ConnString: connStr, explanation: expl}
}

// commonly (to be) used for exposure analysis output formatters
const (
	entireCluster          = "entire-cluster"
	exposureAnalysisHeader = "Exposure Analysis Result:"
	egressExposureHeader   = "Egress Exposure:"
	ingressExposureHeader  = "Ingress Exposure:"
	stringInBrackets       = "[%s]"
	mapOpen                = "{"
	mapClose               = "}"
	comma                  = ","
)

// formSingleExposureConn returns a representation of single exposure connection fields as singleConnFields object
func formSingleExposureConn(peer, repPeer string, conn common.Connection, isIngress bool) singleConnFields {
	connStr := conn.(*common.ConnectionSet).String()
	if isIngress {
		return singleConnFields{Src: repPeer, Dst: peer, ConnString: connStr}
	}
	return singleConnFields{Src: peer, Dst: repPeer, ConnString: connStr}
}

// formExposureItemAsSingleConnFiled returns a singleConnFields object for an item in the XgressExposureData list
func formExposureItemAsSingleConnFiled(peerStr string, exposureItem XgressExposureData, isIngress bool) singleConnFields {
	if exposureItem.IsExposedToEntireCluster() {
		return formSingleExposureConn(peerStr, entireCluster, exposureItem.PotentialConnectivity(), isIngress)
	}
	repPeerStr := getRepresentativeNamespaceString(exposureItem.NamespaceLabels(), true) + "/" +
		getRepresentativePodString(exposureItem.PodLabels(), true)
	return formSingleExposureConn(peerStr, repPeerStr, exposureItem.PotentialConnectivity(), isIngress)
}

// convertLabelsMapToString returns a string representation of the given labels map
func convertLabelsMapToString(labelsMap map[string]string) string {
	return labels.SelectorFromSet(labels.Set(labelsMap)).String()
}

// convertRequirementsToString returns a string representation of the given requirements list
func convertRequirementsToString(reqs []v1.LabelSelectorRequirement) string {
	const strPrefix = "&LabelSelectorRequirement"
	reqStrings := make([]string, len(reqs))
	for i, req := range reqs {
		reqStrings[i] = strings.ReplaceAll(req.String(), strPrefix, "")
	}
	sort.Strings(reqStrings)
	return strings.Join(reqStrings, comma)
}

// writeLabelSelectorAsString returns a string representation of the label selector
func writeLabelSelectorAsString(labelSel v1.LabelSelector) string {
	var res string
	if len(labelSel.MatchLabels) > 0 {
		res = convertLabelsMapToString(labelSel.MatchLabels)
	}
	if len(labelSel.MatchExpressions) > 0 {
		if res != "" {
			res += comma
		}
		res += convertRequirementsToString(labelSel.MatchExpressions)
	}
	return res
}

// getRepresentativeNamespaceString returns a string representation of a potential peer with namespace labels.
// if namespace string is with multiple words, returns it in brackets ([]) in case of textual (non-graphical) output
func getRepresentativeNamespaceString(nsLabels v1.LabelSelector, txtOutFlag bool) string {
	// if ns selector contains only namespace name label - return ns name
	nsName, ok := nsLabels.MatchLabels[common.K8sNsNameLabelKey]
	if len(nsLabels.MatchLabels) == 1 && len(nsLabels.MatchExpressions) == 0 && ok {
		return nsName
	}
	// else if ns labels are empty - res = all namespaces
	var res string
	if nsLabels.Size() == 0 {
		res = allNamespacesLbl
	} else {
		res = "namespace with " + mapOpen + writeLabelSelectorAsString(nsLabels) + mapClose
	}
	if txtOutFlag {
		return fmt.Sprintf(stringInBrackets, res)
	}
	return res
}

// getRepresentativePodString returns a string representation of potential peer with pod labels
// or all pods string for empty pod labels map (which indicates all pods).
// adds [] in case of textual (non-graphical) output
func getRepresentativePodString(podLabels v1.LabelSelector, txtOutFlag bool) string {
	var res string
	if podLabels.Size() == 0 {
		res = allPeersLbl
	} else {
		res = "pod with " + mapOpen + writeLabelSelectorAsString(podLabels) + mapClose
	}
	if txtOutFlag {
		return fmt.Sprintf(stringInBrackets, res)
	}
	return res
}

// following code is common for txt, md, csv and json:

// getConnlistAsSortedSingleConnFieldsArray returns a sorted singleConnFields list from Peer2PeerConnection list.
// creates ipMaps object if the format requires it (to be used for exposure results later)
func getConnlistAsSortedSingleConnFieldsArray(conns []Peer2PeerConnection, ipMaps ipMaps, saveToIPMaps, explain bool) []singleConnFields {
	connItems := make([]singleConnFields, 0)
	for _, conn := range conns {
		if saveToIPMaps {
			ipMaps.saveConnsWithIPs(conn, explain)
		}
		// Note that : for formats other than 'txt' - if the `explain` flag was on for the analyzer -
		// we get here with explain=false (ignored for output) and display regular connlist; However,
		// the analyzer stored empty connections - that we don't want to display them on regular connlist
		if !explain && isEmpty(conn) {
			continue
		}
		connItems = append(connItems, formSingleP2PConn(conn, explain))
	}
	return sortConnFields(connItems, true)
}

// sortConnFields returns sorted list from the given singleConnFields list;
// list may be sorted by src or by dst field as required
func sortConnFields(conns []singleConnFields, sortBySrc bool) []singleConnFields {
	sort.Slice(conns, func(i, j int) bool {
		if sortBySrc {
			if conns[i].Src != conns[j].Src {
				return conns[i].Src < conns[j].Src
			}
			return conns[i].Dst < conns[j].Dst
		} // else sort by dst
		if conns[i].Dst != conns[j].Dst {
			return conns[i].Dst < conns[j].Dst
		}
		return conns[i].Src < conns[j].Src
	})
	return conns
}

// getExposureConnsAsSortedSingleConnFieldsArray returns two sorted singleConnFields of ingress exposure and ingress exposure lists from
// ExposedPeer list and ipMaps records.
// and for txt output use only, returns unprotected peers' lines
func getExposureConnsAsSortedSingleConnFieldsArray(exposureConns []ExposedPeer, ipMaps ipMaps) (ingExposure,
	egExposure []singleConnFields, unprotectedLines []string) {
	for _, ep := range exposureConns {
		pIngExposure, ingUnprotected := getXgressExposureConnsAsSingleConnFieldsArray(ep.ExposedPeer().String(),
			true, ep.IsProtectedByIngressNetpols(), ep.IngressExposure(), ipMaps)
		ingExposure = append(ingExposure, pIngExposure...)
		unprotectedLines = append(unprotectedLines, ingUnprotected...)
		pEgExposure, egUnprotected := getXgressExposureConnsAsSingleConnFieldsArray(ep.ExposedPeer().String(),
			false, ep.IsProtectedByEgressNetpols(), ep.EgressExposure(), ipMaps)
		egExposure = append(egExposure, pEgExposure...)
		unprotectedLines = append(unprotectedLines, egUnprotected...)
	}
	return sortConnFields(ingExposure, false), sortConnFields(egExposure, true), unprotectedLines
}

// getXgressExposureConnsAsSingleConnFieldsArray returns xgress data of an exposed peer as singleConnFields list.
// and for txt output use only, returns also the unprotected line of the peer
// if a peer is not protected, two lines are to be added to exposure analysis result:
// 1. all conns with entire cluster (added here)
// 2. all conns with ip-blocks (all destinations); for sure found in the ip conns map so will be added automatically
// also unprotected line will be added to textual output
func getXgressExposureConnsAsSingleConnFieldsArray(peerStr string, isIngress, isProtected bool,
	xgressExp []XgressExposureData, ipMaps ipMaps) (xgressLines []singleConnFields, xgressUnprotectedLine []string) {
	direction := "Ingress"
	if !isIngress {
		direction = "Egress"
	}
	if !isProtected {
		xgressLines = append(xgressLines, formSingleExposureConn(peerStr, entireCluster, common.MakeConnectionSet(true), isIngress))
		xgressUnprotectedLine = append(xgressUnprotectedLine, peerStr+" is not protected on "+direction)
	} else { // protected
		for _, data := range xgressExp {
			xgressLines = append(xgressLines, formExposureItemAsSingleConnFiled(peerStr, data, isIngress))
		}
	}
	// append xgress ip conns to this peer from the relevant map
	ipMap := ipMaps.PeerToConnsFromIPs
	if !isIngress {
		ipMap = ipMaps.peerToConnsToIPs
	}
	if ipConns, ok := ipMap[peerStr]; ok {
		xgressLines = append(xgressLines, ipConns...)
	}
	return xgressLines, xgressUnprotectedLine
}

// writeExposureSubSection if the list is not empty returns it as string lines with the matching sub section given header
func writeExposureSubSection(lines []string, header string) string {
	res := ""
	if len(lines) > 0 {
		res += header
		res += strings.Join(lines, newLineChar)
		res += newLineChar
	}
	return res
}
