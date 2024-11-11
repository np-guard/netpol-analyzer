/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connlist

import (
	"encoding/json"
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

// writeOutput returns a json string form of connections from list of Peer2PeerConnection objects
// and exposure analysis results from list ExposedPeer if exists
func (j *formatJSON) writeOutput(conns []Peer2PeerConnection, exposureConns []ExposedPeer, exposureFlag bool, explain bool) (string, error) {
	// Tanya TODO - handle explain flag
	j.ipMaps = createIPMaps(exposureFlag)
	// output variables
	var jsonConns []byte
	var err error
	// get an array of sorted connlist items ([]singleConnFields)
	sortedConnItems := getConnlistAsSortedSingleConnFieldsArray(conns, j.ipMaps, exposureFlag, explain)
	if exposureFlag {
		// get an array of sorted exposure items
		ingressExposureItems, egressExposureItems, _ := getExposureConnsAsSortedSingleConnFieldsArray(exposureConns, j.ipMaps)
		jsonOut := jsonFields{
			ConnlistResults: sortedConnItems,
			ExposureResults: exposureFields{
				EgressExposure:  egressExposureItems,
				IngressExposure: ingressExposureItems,
			},
		}
		jsonConns, err = json.MarshalIndent(jsonOut, "", indent)
	} else { // no exposure
		jsonConns, err = json.MarshalIndent(sortedConnItems, "", indent)
	}
	if err != nil {
		return "", err
	}
	return string(jsonConns), nil
}
