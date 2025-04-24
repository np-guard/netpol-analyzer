/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connlist

import "github.com/np-guard/netpol-analyzer/pkg/netpol/internal/formatting"

// formatSVG: implements the connsFormatter interface for svg output format
type formatSVG struct {
	peersList []Peer // internally used peersList; in case of focusWorkload option contains only relevant peers
}

// writeOutput returns a svg string form of connections from list of Peer2PeerConnection objects
// and from exposure-analysis results if exists
// explain input is ignored since not supported with this format
func (s *formatSVG) writeOutput(conns []Peer2PeerConnection, exposureConns []ExposedPeer, exposureFlag, explain bool,
	focusConnStr string) (string, error) {
	// first write dot output
	formatDot := formatDOT{peersList: s.peersList}
	dotOutput, err := formatDot.writeOutput(conns, exposureConns, exposureFlag, explain, focusConnStr)
	if err != nil {
		return "", err
	}
	// generate svg using graphviz (already validated that graphviz is installed)
	return formatting.GenerateSVGWithGraphviz(dotOutput)
}
