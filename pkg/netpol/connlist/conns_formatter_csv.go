/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connlist

import (
	"bytes"
	"encoding/csv"
)

// formatCSV: implements the connsFormatter interface for csv output format
type formatCSV struct {
}

// returns a CSV string form of connections from list of Peer2PeerConnection objects
func (cs formatCSV) writeOutput(conns []Peer2PeerConnection) (string, error) {
	// get an array of sorted conns items ([]singleConnFields)
	sortedConnItems := sortConnections(conns)
	var headerCSV = []string{"src", "dst", "conn"}

	// writing csv rows into a buffer
	buf := new(bytes.Buffer)
	writer := csv.NewWriter(buf)
	if err := writer.Write(headerCSV); err != nil {
		return "", err
	}
	for _, conn := range sortedConnItems {
		row := []string{conn.Src, conn.Dst, conn.ConnString}
		if err := writer.Write(row); err != nil {
			return "", err
		}
	}
	writer.Flush()
	return buf.String(), nil
}
