/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package formatting

import (
	"bytes"
	"errors"
	"os/exec"

	"github.com/np-guard/netpol-analyzer/pkg/internal/output"
)

const graphvizSvgArgs = "-T" + output.SVGFormat

// GenerateSVGWithGraphviz  generate svg string of the given dot string using graphviz (already validated that graphviz is installed)
func GenerateSVGWithGraphviz(dotOutput string) (string, error) {
	// pipe dotOutput as in `echo 'dotOutput' | dot -Tsvg` to write svg output
	cmd := exec.Command(output.GraphvizExecutable, graphvizSvgArgs) //nolint:gosec // nosec
	cmd.Stdin = bytes.NewBufferString(dotOutput)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return "", errors.New(err.Error() + "; " + stderr.String())
	}
	return out.String(), nil
}
