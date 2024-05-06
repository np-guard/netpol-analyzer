/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connlist

import "encoding/json"

// formatJSON: implements the connsFormatter interface for JSON output format
type formatJSON struct {
}

// returns a json string form of connections from list of Peer2PeerConnection objects
func (j formatJSON) writeOutput(conns []Peer2PeerConnection) (string, error) {
	// get an array of sorted conns items ([]singleConnFields)
	sortedConnItems := sortConnections(conns)
	jsonConns, err := json.MarshalIndent(sortedConnItems, "", "  ")
	if err != nil {
		return "", err
	}
	return string(jsonConns), nil
}
