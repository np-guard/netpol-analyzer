/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connlist

import (
	"sort"
	"strings"
)

// formatText: implements the connsFormatter interface for txt output format
type formatText struct {
}

// returns a textual string format of connections from list of Peer2PeerConnection objects
func (t formatText) writeOutput(conns []Peer2PeerConnection) (string, error) {
	connLines := make([]string, len(conns))
	for i := range conns {
		connLines[i] = formSingleConn(conns[i]).string()
	}
	sort.Strings(connLines)
	return strings.Join(connLines, newLineChar), nil
}
