/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connlist

import (
	"bytes"
	"encoding/csv"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// formatCSV: implements the connsFormatter interface for csv output format
type formatCSV struct {
	ipMaps ipMaps
}

// writeOutput returns a CSV string form of connections from list of Peer2PeerConnection objects
// and exposure analysis results from list ExposedPeer if exists
// explain input is ignored since not supported with this format
func (cs *formatCSV) writeOutput(conns []Peer2PeerConnection, exposureConns []ExposedPeer, exposureFlag, explain bool,
	focusConn *common.ConnectionSet) (string, error) {
	// writing csv rows into a buffer
	buf := new(bytes.Buffer)
	writer := csv.NewWriter(buf)

	err := cs.writeCsvConnlistTable(conns, writer, exposureFlag, false, focusConn)
	if err != nil {
		return "", err
	}
	if exposureFlag {
		err = cs.writeCsvExposureTable(exposureConns, writer, focusConn)
		if err != nil {
			return "", err
		}
	}
	writer.Flush()
	return buf.String(), nil
}

// writeCsvColumnsHeader writes columns header row
func writeCsvColumnsHeader(writer *csv.Writer, srcFirst bool, focusConn *common.ConnectionSet) error {
	headerCSV := []string{src, dst, conn}
	if focusConn != nil {
		headerCSV = []string{src, dst}
	}
	if !srcFirst {
		headerCSV = []string{dst, src, conn}
		if focusConn != nil {
			headerCSV = []string{dst, src}
		}
	}
	return writer.Write(headerCSV)
}

// writeTableRows writes the given connections list as csv table
func writeTableRows(conns []singleConnFields, writer *csv.Writer, srcFirst bool, focusConn *common.ConnectionSet) error {
	for _, conn := range conns {
		row := []string{conn.Src, conn.Dst, conn.ConnString}
		if focusConn != nil {
			row = []string{conn.Src, conn.Dst}
		}
		if !srcFirst {
			row = []string{conn.Dst, conn.Src, conn.ConnString}
			if focusConn != nil {
				row = []string{conn.Dst, conn.Src}
			}
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	return nil
}

// writeCsvConnlistTable writes csv table for the Peer2PeerConnection list
func (cs *formatCSV) writeCsvConnlistTable(conns []Peer2PeerConnection, writer *csv.Writer, saveIPConns, explain bool,
	focusConn *common.ConnectionSet) error {
	err := writeCsvColumnsHeader(writer, true, focusConn)
	if err != nil {
		return err
	}
	cs.ipMaps = createIPMaps(saveIPConns)
	// get an array of sorted conns items ([]singleConnFields), if required also save the relevant conns to ipMaps
	sortedConnItems := getConnlistAsSortedSingleConnFieldsArray(conns, cs.ipMaps, saveIPConns, explain)
	return writeTableRows(sortedConnItems, writer, true, focusConn)
}

// writeCsvExposureTable writes csv table for ExposedPeer list
func (cs *formatCSV) writeCsvExposureTable(exposureConns []ExposedPeer, writer *csv.Writer, focusConn *common.ConnectionSet) error {
	ingressExposure, egressExposure, _ := getExposureConnsAsSortedSingleConnFieldsArray(exposureConns, cs.ipMaps)
	// start new section for exposure analysis
	expHeader := exposureAnalysisHeader
	if focusConn != nil {
		expHeader += onStr + focusConn.String()
	}
	expHeader += colon
	err := writer.Write([]string{expHeader, "", ""})
	if err != nil {
		return err
	}
	err = writeCsvSubSection(egressExposure, false, writer, focusConn)
	if err != nil {
		return err
	}
	return writeCsvSubSection(ingressExposure, true, writer, focusConn)
}

// writeCsvSubSection writes new csv table with its headers for the given xgress section
func writeCsvSubSection(expData []singleConnFields, isIngress bool, writer *csv.Writer, focusConn *common.ConnectionSet) error {
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
	err = writeCsvColumnsHeader(writer, !isIngress, focusConn)
	if err != nil {
		return err
	}
	return writeTableRows(expData, writer, !isIngress, focusConn)
}
