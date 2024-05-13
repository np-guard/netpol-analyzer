/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package diff

import (
	"fmt"
	"strings"
)

// diffFormatText: implements the diffFormatter interface for txt output format
type diffFormatText struct {
	ref1 string
	ref2 string
}

const (
	// txt output header
	connectivityDiffHeader = "Connectivity diff:"
)

// returns a textual string format of connections diff from connectivityDiff object
func (t *diffFormatText) writeDiffOutput(connsDiff ConnectivityDiff) (string, error) {
	res := make([]string, 0)
	res = append(res, connectivityDiffHeader)
	res = append(res, writeDiffLinesOrderedByCategory(connsDiff, t)...)
	return strings.Join(res, newLine), nil
}

// singleDiffLine forms a single diff line in the txt format
func (t *diffFormatText) singleDiffLine(d *singleDiffFields) string {
	diffLine := fmt.Sprintf("diff-type: %s, source: %s, destination: %s, %s: %s, %s: %s", d.diffType,
		d.src, d.dst, t.ref1, d.ref1Conn, t.ref2, d.ref2Conn)
	if d.workloadDiffInfo != "" {
		return diffLine + ", workloads-diff-info: " + d.workloadDiffInfo
	}
	return diffLine
}
