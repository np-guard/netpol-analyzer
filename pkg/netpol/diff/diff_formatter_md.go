package diff

import (
	"fmt"
	"strings"
)

// diffFormatMD: implements the diffFormatter interface for md output format
type diffFormatMD struct {
}

var mdHeader = "| diff-type | source | destination | dir1 | dir2 | workloads-diff-info |\n" +
	"|-----------|--------|-------------|------|------|---------------------|"

// returns md string format of connections diff from connectivityDiff object
func (md *diffFormatMD) writeDiffOutput(connsDiff ConnectivityDiff) (string, error) {
	res := make([]string, 0)
	res = append(res, mdHeader)
	res = append(res, writeDiffLinesOrderedByCategory(connsDiff, md)...)
	return strings.Join(res, newLine), nil
}

// singleDiffLine forms a single diff line in the md format
func (md *diffFormatMD) singleDiffLine(d *singleDiffFields) string {
	return fmt.Sprintf("| %s | %s | %s | %s | %s | %s |",
		d.diffType, d.src, d.dst, d.dir1Conn, d.dir2Conn, d.workloadDiffInfo)
}
