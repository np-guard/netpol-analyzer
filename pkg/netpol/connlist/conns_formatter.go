package connlist

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
)

func getNewLineChar() string {
	return fmt.Sprintln("")
}

// gets the conns array and returns a sorted array of singleConnFields struct. helps with forming the json and csv outputs
func writeConnsIntoSortedSingleConnFieldsArray(conns []Peer2PeerConnection) []singleConnFields {
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

	return connItems
}

// connsFormatter implements output formatting in the required output format
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
func (c singleConnFields) string() string {
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
		connLines[i] = formSingleConn(conns[i]).string()
	}
	sort.Strings(connLines)
	return strings.Join(connLines, getNewLineChar()), nil
}

// jsonFormatter: implements the connsFormatter interface for JSON output format
type jsonFormatter struct {
}

// returns a json string form of connections from list of Peer2PeerConnection objects
func (j jsonFormatter) writeOutput(conns []Peer2PeerConnection) (string, error) {
	// get an array of sorted conns items ([]singleConnFields)
	sortedConnItems := writeConnsIntoSortedSingleConnFieldsArray(conns)
	jsonConns, err := json.MarshalIndent(sortedConnItems, "", "  ")
	if err != nil {
		return "", err
	}
	return string(jsonConns), nil
}

// dotFormatter: implements the connsFormatter interface for dot output format
type dotFormatter struct {
}

const (
	dotHeader  = "digraph {"
	dotClosing = "}"
)

// formats an edge line from a singleConnFields struct , to be used for dot graph
func getEdgeLine(c singleConnFields) string {
	return fmt.Sprintf("\t%q -> %q [label=%q color=\"gold2\" fontcolor=\"darkgreen\"]", c.Src, c.Dst, c.ConnString)
}

// formats a peer line for dot graph
func getPeerLine(peer eval.Peer) string {
	var peerColor string
	if peer.IsPeerIPType() {
		peerColor = "red2"
	} else {
		peerColor = "blue"
	}
	peerName := peer.String()
	return fmt.Sprintf("\t%q [label=%q color=%q fontcolor=%q]", peerName, peerName, peerColor, peerColor)
}

// returns a dot string form of connections from list of Peer2PeerConnection objects
func (d dotFormatter) writeOutput(conns []Peer2PeerConnection) (string, error) {
	edgeLines := make([]string, len(conns))      // list of edges lines
	peersVisited := make(map[string]struct{}, 0) // acts as a set
	peerLines := make([]string, 0)               // list of peers lines
	for index := range conns {
		connLine := formSingleConn(conns[index])
		edgeLines[index] = getEdgeLine(connLine)
		if _, ok := peersVisited[connLine.Src]; !ok {
			peersVisited[connLine.Src] = struct{}{}
			peerLines = append(peerLines, getPeerLine(conns[index].Src()))
		}
		if _, ok := peersVisited[connLine.Dst]; !ok {
			peersVisited[connLine.Dst] = struct{}{}
			peerLines = append(peerLines, getPeerLine(conns[index].Dst()))
		}
	}
	// sort graph lines
	sort.Strings(peerLines)
	sort.Strings(edgeLines)
	// collect all lines by order
	allLines := []string{dotHeader}
	allLines = append(allLines, peerLines...)
	allLines = append(allLines, edgeLines...)
	allLines = append(allLines, dotClosing)
	return strings.Join(allLines, getNewLineChar()), nil
}

// csvFormatter: implements the connsFormatter interface for csv output format
type csvFormatter struct {
}

// returns a csv string form of connections from list of Peer2PeerConnection objects
func (cs csvFormatter) writeOutput(conns []Peer2PeerConnection) (string, error) {
	// get an array of sorted conns items ([]singleConnFields)
	sortedConnItems := writeConnsIntoSortedSingleConnFieldsArray(conns)
	var csvHeader = []string{"src", "dst", "conn"}

	// writing csv rows into a buffer
	buf := new(bytes.Buffer)
	writer := csv.NewWriter(buf)
	if err := writer.Write(csvHeader); err != nil {
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
