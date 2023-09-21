package diff

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strings"
)

// diffFormatCSV: implements the diffFormatter interface for csv output format
type diffFormatCSV struct {
}

var csvHeader = []string{"diff-type", "source", "destination", "dir1", "dir2", "workloads-diff-info"}

// writeDiffOutput writes the diff output in the csv format
func (cs *diffFormatCSV) writeDiffOutput(connsDiff ConnectivityDiff) (string, error) {
	changesSortedByCategory := writeDiffLinesOrderedByCategory(connsDiff, cs)
	// writing csv rows into a buffer
	buf := new(bytes.Buffer)
	writer := csv.NewWriter(buf)
	if err := writer.Write(csvHeader); err != nil {
		return "", err
	}
	for _, diffData := range changesSortedByCategory {
		row := strings.Split(diffData, ";")
		if err := writer.Write(row); err != nil {
			return "", err
		}
	}
	writer.Flush()
	return buf.String(), nil
}

// singleDiffLine forms a single diff line in the csv format
func (cs *diffFormatCSV) singleDiffLine(d *singleDiffFields) string {
	return fmt.Sprintf("%s;%s;%s;%s;%s;%s", d.diffType, d.src, d.dst, d.dir1Conn, d.dir2Conn, d.workloadDiffInfo)
}
