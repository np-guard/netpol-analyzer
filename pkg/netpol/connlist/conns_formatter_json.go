package connlist

import "encoding/json"

// formatJSON: implements the connsFormatter interface for JSON output format
type formatJSON struct {
}

// returns a json string form of connections from list of Peer2PeerConnection objects
// this format is not supported with exposure analysis; exposureConns is not used;
func (j *formatJSON) writeOutput(conns []Peer2PeerConnection, exposureConns []ExposedPeer) (string, error) {
	// get an array of sorted conns items ([]singleConnFields)
	sortedConnItems := sortConnections(conns)
	jsonConns, err := json.MarshalIndent(sortedConnItems, "", "  ")
	if err != nil {
		return "", err
	}
	return string(jsonConns), nil
}
