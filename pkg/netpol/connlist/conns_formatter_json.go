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
	ExposureResults []singleConnFields `json:"exposure_results"`
}

// writeOutput returns a json string form of connections from list of Peer2PeerConnection objects
// and exposure analysis results from list ExposedPeer if exists
func (j *formatJSON) writeOutput(conns []Peer2PeerConnection, exposureConns []ExposedPeer, exposureFlag bool) (string, error) {
	j.ipMaps = createIPMaps(exposureFlag)
	// output variables
	var jsonConns []byte
	var err error
	// get an array of sorted connlist items ([]singleConnFields)
	sortedConnItems := getConnlistAsSortedSingleConnFieldsArray(conns, j.ipMaps, exposureFlag)
	if exposureFlag {
		// get an array of sorted exposure items
		exposureConnItems := getExposureConnsAsSortedSingleConnFieldsArray(exposureConns, j.ipMaps)
		jsonOut := jsonFields{ConnlistResults: sortedConnItems, ExposureResults: exposureConnItems}
		jsonConns, err = json.MarshalIndent(jsonOut, "", indent)
	} else { // no exposure
		jsonConns, err = json.MarshalIndent(sortedConnItems, "", indent)
	}
	if err != nil {
		return "", err
	}
	return string(jsonConns), nil
}
