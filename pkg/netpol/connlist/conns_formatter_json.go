/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connlist

import (
	"encoding/json"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
)

// formatJSON: implements the connsFormatter interface for JSON output format
type formatJSON struct {
	ipMaps ipMaps
}

const indent = "  "

type jsonFields struct {
	ConnlistResults []singleConnFields `json:"connlist_results"`
	ExposureResults exposureFields     `json:"exposure_results"`
}

type exposureFields struct {
	EgressExposure  []singleConnFields `json:"egress_exposure"`
	IngressExposure []singleConnFields `json:"ingress_exposure"`
}

type jsonFocusConnFields struct {
	ConnlistResults []singleSrcDstFields    `json:"connlist_conn_focus_results"`
	ExposureResults exposureFocusConnFields `json:"exposure_conn_focus_results"`
}

type exposureFocusConnFields struct {
	EgressExposure  []singleSrcDstFields `json:"egress_exposure"`
	IngressExposure []singleSrcDstFields `json:"ingress_exposure"`
}

// writeOutput returns a json string form of connections from list of Peer2PeerConnection objects
// and exposure analysis results from list ExposedPeer if exists
// explain input is ignored since not supported with this format
func (j *formatJSON) writeOutput(conns []Peer2PeerConnection, exposureConns []ExposedPeer, exposureFlag, explain bool,
	focusConnStr string, primaryUdnNamespaces map[string]eval.UDNData) (string, error) {
	j.ipMaps = createIPMaps(exposureFlag)
	// output variables
	var jsonConns []byte
	var err error
	// get an array of sorted connlist items ([]singleConnFields)
	sortedConnItems := getConnlistAsSortedSingleConnFieldsArray(conns, j.ipMaps, exposureFlag, false, primaryUdnNamespaces)
	if exposureFlag {
		// get an array of sorted exposure items
		ingressExposureItems, egressExposureItems, _ := getExposureConnsAsSortedSingleConnFieldsArray(exposureConns, j.ipMaps)
		if focusConnStr == "" {
			jsonOut := writeAllConnsJSONFields(sortedConnItems, ingressExposureItems, egressExposureItems)
			jsonConns, err = json.MarshalIndent(jsonOut, "", indent)
		} else {
			jsonFocusConnOut := writeFocusConnsJSONFields(sortedConnItems, ingressExposureItems, egressExposureItems)
			jsonConns, err = json.MarshalIndent(jsonFocusConnOut, "", indent)
		}
	} else { // no exposure
		if focusConnStr == "" {
			jsonConns, err = json.MarshalIndent(sortedConnItems, "", indent)
		} else {
			jsonConns, err = json.MarshalIndent(getListWithoutConnData(sortedConnItems), "", indent)
		}
	}
	if err != nil {
		return "", err
	}
	return string(jsonConns), nil
}

func writeAllConnsJSONFields(sortedConnItems, ingressExposureItems, egressExposureItems []singleConnFields) jsonFields {
	return jsonFields{
		ConnlistResults: sortedConnItems,
		ExposureResults: exposureFields{
			EgressExposure:  egressExposureItems,
			IngressExposure: ingressExposureItems,
		},
	}
}

func writeFocusConnsJSONFields(sortedConnItems, ingressExposureItems, egressExposureItems []singleConnFields) jsonFocusConnFields {
	sortedConnItemsWithoutConnData := getListWithoutConnData(sortedConnItems)
	ingressExposureItemsWithoutConnData := getListWithoutConnData(ingressExposureItems)
	egressExposureItemsWithoutConnData := getListWithoutConnData(egressExposureItems)

	return jsonFocusConnFields{
		ConnlistResults: sortedConnItemsWithoutConnData,
		ExposureResults: exposureFocusConnFields{
			EgressExposure:  egressExposureItemsWithoutConnData,
			IngressExposure: ingressExposureItemsWithoutConnData,
		},
	}
}

type singleSrcDstFields struct {
	Src string `json:"src"`
	Dst string `json:"dst"`
}

func getListWithoutConnData(items []singleConnFields) []singleSrcDstFields {
	res := make([]singleSrcDstFields, len(items))
	for i := range items {
		res[i] = singleSrcDstFields{Src: items[i].Src, Dst: items[i].Dst}
	}
	return res
}
