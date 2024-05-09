/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connlist

import (
	"fmt"
	"sort"
	"strings"
)

// formatMD: implements the connsFormatter interface for md output format
type formatMD struct {
}

// formats the md output header
func getMDHeader() string {
	return "| src | dst | conn |\n|-----|-----|------|"
}

// formats a connection line for md output
func getMDLine(c singleConnFields) string {
	return fmt.Sprintf("| %s | %s | %s |", c.Src, c.Dst, c.ConnString)
}

// returns a md string form of connections from list of Peer2PeerConnection objects
// this format is not supported with exposure analysis; exposureConns is not used;
func (md *formatMD) writeOutput(conns []Peer2PeerConnection, exposureConns []ExposedPeer) (string, error) {
	mdLines := make([]string, len(conns))
	for index := range conns {
		mdLines[index] = getMDLine(formSingleP2PConn(conns[index]))
	}
	sort.Strings(mdLines)
	allLines := []string{getMDHeader()}
	allLines = append(allLines, mdLines...)
	return strings.Join(allLines, newLineChar), nil
}
