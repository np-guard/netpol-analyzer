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
	ipMaps ipMaps
}

// writeOutput returns a CSV string form of connections from list of Peer2PeerConnection objects
// and exposure analysis results from list ExposedPeer if exists
func (cs *formatCSV) writeOutput(conns []Peer2PeerConnection, exposureConns []ExposedPeer) (string, error) {
	exposureFlag := len(exposureConns) > 0
	// writing csv rows into a buffer
	buf := new(bytes.Buffer)
	writer := csv.NewWriter(buf)

	err := cs.writeCsvConnlistTable(conns, writer, exposureFlag)
	if err != nil {
		return "", err
	}
	if exposureFlag {
		err = cs.writeCsvExposureTable(exposureConns, writer)
		if err != nil {
			return "", err
		}
	}
	writer.Flush()
	return buf.String(), nil
}

// writeCsvColumnsHeader writes columns header row
func writeCsvColumnsHeader(writer *csv.Writer) error {
	var headerCSV = []string{"src", "dst", "conn"}
	return writer.Write(headerCSV)
}

// writeTableRows writes the given connections list as csv table
func writeTableRows(conns []singleConnFields, writer *csv.Writer) error {
	for _, conn := range conns {
		row := []string{conn.Src, conn.Dst, conn.ConnString}
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	return nil
}

// writeCsvConnlistTable writes csv table for the Peer2PeerConnection list
func (cs *formatCSV) writeCsvConnlistTable(conns []Peer2PeerConnection, writer *csv.Writer, saveIPConns bool) error {
	err := writeCsvColumnsHeader(writer)
	if err != nil {
		return err
	}
	cs.ipMaps = createIPMaps(saveIPConns)
	// get an array of sorted conns items ([]singleConnFields), if required also save the relevant conns to ipMaps
	sortedConnItems := getConnlistAsSortedSingleConnFieldsArray(conns, cs.ipMaps, saveIPConns)
	return writeTableRows(sortedConnItems, writer)
}

// writeCsvExposureTable writes csv table for ExposedPeer list
func (cs *formatCSV) writeCsvExposureTable(exposureConns []ExposedPeer, writer *csv.Writer) error {
	exposureRecords := getExposureConnsAsSortedSingleConnFieldsArray(exposureConns, cs.ipMaps)
	// start new section for exposure analysis
	err := writer.Write([]string{exposureAnalysisHeader, "", ""})
	if err != nil {
		return err
	}
	err = writeCsvColumnsHeader(writer)
	if err != nil {
		return err
	}
	return writeTableRows(exposureRecords, writer)
}
