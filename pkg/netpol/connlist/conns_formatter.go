/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connlist

import (
	"fmt"
	"sort"
	"strings"

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
func (i *ipMaps) saveConnsWithIPs(conn Peer2PeerConnection) {
	if conn.Src().IsPeerIPType() {
		i.PeerToConnsFromIPs[conn.Dst().String()] = append(i.PeerToConnsFromIPs[conn.Dst().String()], formSingleP2PConn(conn))
	}
	if conn.Dst().IsPeerIPType() {
		i.peerToConnsToIPs[conn.Src().String()] = append(i.peerToConnsToIPs[conn.Src().String()], formSingleP2PConn(conn))
	}
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
	writeOutput(conns []Peer2PeerConnection, exposureConns []ExposedPeer, exposureFlag bool) (string, error)
}

// singleConnFields represents a single connection object
type singleConnFields struct {
	Src        string `json:"src"`
	Dst        string `json:"dst"`
	ConnString string `json:"conn"`
}

// string representation of the singleConnFields struct
func (c singleConnFields) string() string {
	return fmt.Sprintf("%s => %s : %s", c.Src, c.Dst, c.ConnString)
}

// formSingleP2PConn returns a string representation of single connection fields as singleConnFields object
func formSingleP2PConn(conn Peer2PeerConnection) singleConnFields {
	connStr := common.ConnStrFromConnProperties(conn.AllProtocolsAndPorts(), conn.ProtocolsAndPorts())
	return singleConnFields{Src: conn.Src().String(), Dst: conn.Dst().String(), ConnString: connStr}
}

// commonly (to be) used for exposure analysis output formatters
const (
	entireCluster    = "entire-cluster"
	stringInBrackets = "[%s]"
	mapOpen          = "{"
	mapClose         = "}"
	equal            = "="
	comma            = ","
	key              = "key"
	colon            = ": "
	space            = " "
	notIn            = "NotIn"
	doesNotExist     = "DoesNotExist"
	exists           = "Exists"
	exposureAnalysisHeader = "Exposure Analysis Result:"
	egressExposureHeader   = "Egress Exposure:"
	ingressExposureHeader  = "Ingress Exposure:"
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
// considers the special labels (with requirements such as Exists, DoesNotExist, NotIn)
func convertLabelsMapToString(labelsMap map[string]string) string {
	labelsSrings := make([]string, 0)
	for k, v := range labelsMap {
		if v == common.ExistsVal {
			labelsSrings = append(labelsSrings, k+space+exists)
			continue
		}
		if v == common.DoesNotExistVal {
			labelsSrings = append(labelsSrings, k+space+doesNotExist)
			continue
		}
		if strings.HasPrefix(v, common.NotPrefix) {
			labelsSrings = append(labelsSrings, k+space+notIn+space+v[1:])
			continue
		}
		labelsSrings = append(labelsSrings, k+equal+v)
	}
	sort.Strings(labelsSrings)
	return mapOpen + strings.Join(labelsSrings, comma) + mapClose
}

// getRepresentativeNamespaceString returns a string representation of a potential peer with namespace labels.
// if namespace with multiple words adds [] , in case of textual (non-graphical) output
func getRepresentativeNamespaceString(nsLabels map[string]string, txtOutFlag bool) string {
	nsName, ok := nsLabels[common.K8sNsNameLabelKey]
	if len(nsLabels) == 1 && ok {
		return nsName
	}
	res := ""
	if len(nsLabels) > 0 {
		res += "namespace with " + convertLabelsMapToString(nsLabels)
	} else {
		res += allNamespacesLbl
	}
	if txtOutFlag {
		return fmt.Sprintf(stringInBrackets, res)
	}
	return res
}

// getRepresentativePodString returns a string representation of potential peer with pod labels
// or all pods string for empty pod labels map (which indicates all pods).
// adds [] in case of textual (non-graphical) output
func getRepresentativePodString(podLabels map[string]string, txtOutFlag bool) string {
	res := ""
	if len(podLabels) == 0 {
		res += allPeersLbl
	} else {
		res += "pod with " + convertLabelsMapToString(podLabels)
	}
	if txtOutFlag {
		return fmt.Sprintf(stringInBrackets, res)
	}
	return res
}

// following code is common for txt, md, csv and json:

// getConnlistAsSortedSingleConnFieldsArray returns a sorted singleConnFields list from Peer2PeerConnection list.
// creates ipMaps object if the format requires it (to be used for exposure results later)
func getConnlistAsSortedSingleConnFieldsArray(conns []Peer2PeerConnection, ipMaps ipMaps, saveToIPMaps bool) []singleConnFields {
	connItems := make([]singleConnFields, len(conns))
	for i := range conns {
		if saveToIPMaps {
			ipMaps.saveConnsWithIPs(conns[i])
		}
		connItems[i] = formSingleP2PConn(conns[i])
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
