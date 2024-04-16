package connlist

import (
	"bytes"
	"encoding/csv"
)

// formatCSV: implements the connsFormatter interface for csv output format
type formatCSV struct {
}

// returns a CSV string form of connections from list of Peer2PeerConnection objects
// this format is not supported with exposure analysis; exposureConns is not used;
func (cs *formatCSV) writeOutput(conns []Peer2PeerConnection, exposureConns []ExposedPeer) (string, error) {
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
