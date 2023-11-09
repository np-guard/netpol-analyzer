package diff

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strings"
)

// diffFormatCSV: implements the diffFormatter interface for csv output format
type diffFormatCSV struct {
	ref1 string
	ref2 string
}

func (cs *diffFormatCSV) getCSVHeader() []string {
	return []string{"diff-type", "source", "destination", cs.ref1, cs.ref2, "workloads-diff-info"}
}

// writeDiffOutput writes the diff output in the csv format
func (cs *diffFormatCSV) writeDiffOutput(connsDiff ConnectivityDiff) (string, error) {
	changesSortedByCategory := writeDiffLinesOrderedByCategory(connsDiff, cs)
	// writing csv rows into a buffer
	buf := new(bytes.Buffer)
	writer := csv.NewWriter(buf)
	if err := writer.Write(cs.getCSVHeader()); err != nil {
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
	return fmt.Sprintf("%s;%s;%s;%s;%s;%s", d.diffType, d.src, d.dst, d.ref1Conn, d.ref2Conn, d.workloadDiffInfo)
}
