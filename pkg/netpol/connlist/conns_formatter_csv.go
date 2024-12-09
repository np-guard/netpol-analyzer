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
func (cs *formatCSV) writeOutput(conns []Peer2PeerConnection, exposureConns []ExposedPeer, exposureFlag, explain bool) (string, error) {
	// Tanya TODO - handle explain flag
	// writing csv rows into a buffer
	buf := new(bytes.Buffer)
	writer := csv.NewWriter(buf)

	err := cs.writeCsvConnlistTable(conns, writer, exposureFlag, explain)
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
func writeCsvColumnsHeader(writer *csv.Writer, srcFirst bool) error {
	headerCSV := []string{src, dst, conn}
	if !srcFirst {
		headerCSV = []string{dst, src, conn}
	}
	return writer.Write(headerCSV)
}

// writeTableRows writes the given connections list as csv table
func writeTableRows(conns []singleConnFields, writer *csv.Writer, srcFirst bool) error {
	for _, conn := range conns {
		row := []string{conn.Src, conn.Dst, conn.ConnString}
		if !srcFirst {
			row = []string{conn.Dst, conn.Src, conn.ConnString}
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	return nil
}

// writeCsvConnlistTable writes csv table for the Peer2PeerConnection list
func (cs *formatCSV) writeCsvConnlistTable(conns []Peer2PeerConnection, writer *csv.Writer, saveIPConns, explain bool) error {
	err := writeCsvColumnsHeader(writer, true)
	if err != nil {
		return err
	}
	cs.ipMaps = createIPMaps(saveIPConns)
	// get an array of sorted conns items ([]singleConnFields), if required also save the relevant conns to ipMaps
	sortedConnItems := getConnlistAsSortedSingleConnFieldsArray(conns, cs.ipMaps, saveIPConns, explain)
	return writeTableRows(sortedConnItems, writer, true)
}

// writeCsvExposureTable writes csv table for ExposedPeer list
func (cs *formatCSV) writeCsvExposureTable(exposureConns []ExposedPeer, writer *csv.Writer) error {
	ingressExposure, egressExposure, _ := getExposureConnsAsSortedSingleConnFieldsArray(exposureConns, cs.ipMaps)
	// start new section for exposure analysis
	err := writer.Write([]string{exposureAnalysisHeader, "", ""})
	if err != nil {
		return err
	}
	err = writeCsvSubSection(egressExposure, false, writer)
	if err != nil {
		return err
	}
	return writeCsvSubSection(ingressExposure, true, writer)
}

// writeCsvSubSection writes new csv table with its headers for the given xgress section
func writeCsvSubSection(expData []singleConnFields, isIngress bool, writer *csv.Writer) error {
	if len(expData) == 0 {
		return nil
	}
	subHeader := egressExposureHeader
	if isIngress {
		subHeader = ingressExposureHeader
	}
	err := writer.Write([]string{subHeader, "", ""})
	if err != nil {
		return err
	}
	err = writeCsvColumnsHeader(writer, !isIngress)
	if err != nil {
		return err
	}
	return writeTableRows(expData, writer, !isIngress)
}
