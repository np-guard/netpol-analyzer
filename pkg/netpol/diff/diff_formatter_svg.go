/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package diff

import (
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/formatting"
)

// diffFormatSVG: implements the diffFormatter interface for svg output format
type diffFormatSVG struct {
	ref1 string
	ref2 string
}

// writeDiffOutput writes the diff output in the svg format
func (s *diffFormatSVG) writeDiffOutput(connsDiff ConnectivityDiff) (string, error) {
	// first write dot output
	formatDot := diffFormatDOT{ref1: s.ref1, ref2: s.ref2}
	dotOutput, err := formatDot.writeDiffOutput(connsDiff)
	if err != nil {
		return "", err
	}
	// generate svg using graphviz (already validated that graphviz is installed)
	return formatting.GenerateSVGWithGraphviz(dotOutput)
}

// kept empty for svg format, used to implement the diffFormatter interface in other formats
func (s *diffFormatSVG) singleDiffLine(d *singleDiffFields) string {
	return ""
}
