package connlist

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// connsFormatter implements output  formatting in the required output format
type connsFormatter interface {
	writeOutput(conns []Peer2PeerConnection) (string, error)
}

// singleConnFields represents a single connection object
type singleConnFields struct {
	Src        string `json:"src"`
	Dst        string `json:"dst"`
	ConnString string `json:"conn"`
}

// string representation of the singleConnFields struct
func (c singleConnFields) String() string {
	return fmt.Sprintf("%s => %s : %s", c.Src, c.Dst, c.ConnString)
}

// formSingleConn returns a string representation of single connection fields as singleConnFields object
func formSingleConn(conn Peer2PeerConnection) singleConnFields {
	connStr := getProtocolsAndPortsStr(conn)
	return singleConnFields{Src: conn.Src().String(), Dst: conn.Dst().String(), ConnString: connStr}
}

// txtFormatter: implements the connsFormatter interface for txt output format
type txtFormatter struct {
}

// returns a textual string format of connections from list of Peer2PeerConnection objects
func (t txtFormatter) writeOutput(conns []Peer2PeerConnection) (string, error) {
	connLines := make([]string, len(conns))
	for i := range conns {
		connLines[i] = formSingleConn(conns[i]).String()
	}
	sort.Strings(connLines)
	newlineChar := fmt.Sprintln("")
	return strings.Join(connLines, newlineChar), nil
}

// JSONFormatter: implements the ConnsFormatter interface for JSON output format
type jsonFormatter struct {
}

// returns a json string form of connections from list of Peer2PeerConnection objects
func (j jsonFormatter) writeOutput(conns []Peer2PeerConnection) (string, error) {
	connItems := make([]singleConnFields, len(conns))
	for i := range conns {
		connItems[i] = formSingleConn(conns[i])
	}
	sort.Slice(connItems, func(i, j int) bool {
		if connItems[i].Src != connItems[j].Src {
			return connItems[i].Src < connItems[j].Src
		}
		return connItems[i].Dst < connItems[j].Dst
	})
	jsonConns, err := json.MarshalIndent(connItems, "", "  ")
	if err != nil {
		return "", err
	}
	return string(jsonConns), nil
}
