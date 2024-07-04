/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dotformatting

import (
	"fmt"
	"sort"
	"strings"
)

// common dot output formatting consts and funcs
const (
	DotHeader       = "digraph {"
	DotClosing      = "}"
	EdgeWeightLabel = "weight"
	LessWeight      = "0.5"
	MoreWeight      = "1"
)

// AddPeerToNsGroup adds the peer line to the namespace list in the given map.
func AddPeerToNsGroup(peerNs, peerLine string, mapNsToPeers map[string][]string) {
	if _, ok := mapNsToPeers[peerNs]; !ok {
		mapNsToPeers[peerNs] = []string{}
	}
	mapNsToPeers[peerNs] = append(mapNsToPeers[peerNs], "\t"+peerLine) // adding tab to the subgraph's lines
}

// return the label of a cluster's peer to be displayed on its node in the dot graph
func NodeClusterPeerLabel(name, kind string) string {
	return name + "[" + kind + "]"
}

// AddNsGroups gets namespace to peers-lines map, writes a dot subgraph for each namespace with its peers' lines
// returns all subgraphs sorted by namespace name and each subgraph internally sorted by peers' names
func AddNsGroups(nsPeersMap map[string][]string) []string {
	res := []string{}
	// sort namespaces (map's keys) to ensure same output always
	nsKeys := sortMapKeys(nsPeersMap)
	// write ns groups
	for _, ns := range nsKeys {
		peersLines := nsPeersMap[ns]
		sort.Strings(peersLines)
		// create ns  subgraph cluster
		nsLabel := strings.ReplaceAll(ns, "-", "_")                 // dot format does not accept "-" in its sub-graphs names (headers)
		nsLines := []string{"\tsubgraph cluster_" + nsLabel + " {"} // subgraph header
		nsLines = append(nsLines, peersLines...)
		nsLines = append(nsLines, "\t\tlabel=\""+ns+"\"", "\t}")
		// add ns section to the res
		res = append(res, nsLines...)
	}
	return res
}

func sortMapKeys(nsPeersMap map[string][]string) []string {
	keys := make([]string, 0, len(nsPeersMap))
	for k := range nsPeersMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// returns a single edge line string in the dot format
func GetEdgeLine(src, dst, connStr, edgeColor, fontColor string) string {
	var weight string
	if src <= dst {
		weight = LessWeight
	} else {
		weight = MoreWeight
	}
	return fmt.Sprintf("\t%q -> %q [label=%q color=%q fontcolor=%q %s=%s]",
		src, dst, connStr, edgeColor, fontColor, EdgeWeightLabel, weight)
}
