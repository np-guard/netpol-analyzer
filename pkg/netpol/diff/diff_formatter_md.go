/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package diff

import (
	"fmt"
	"strings"
)

// diffFormatMD: implements the diffFormatter interface for md output format
type diffFormatMD struct {
	ref1 string
	ref2 string
}

func (md *diffFormatMD) getMDHeader() string {
	return fmt.Sprintf("| diff-type | source | destination | %s | %s | workloads-diff-info |\n", md.ref1, md.ref2) +
		"|-----------|--------|-------------|------|------|---------------------|"
}

// returns md string format of connections diff from connectivityDiff object
func (md *diffFormatMD) writeDiffOutput(connsDiff ConnectivityDiff) (string, error) {
	res := make([]string, 0)
	res = append(res, md.getMDHeader())
	res = append(res, writeDiffLinesOrderedByCategory(connsDiff, md)...)
	return strings.Join(res, newLine), nil
}

// singleDiffLine forms a single diff line in the md format
func (md *diffFormatMD) singleDiffLine(d *singleDiffFields) string {
	return fmt.Sprintf("| %s | %s | %s | %s | %s | %s |",
		d.diffType, d.src, d.dst, d.ref1Conn, d.ref2Conn, d.workloadDiffInfo)
}
