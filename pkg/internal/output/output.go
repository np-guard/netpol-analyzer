/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package output

import (
	"errors"
	"os"
	"os/exec"

	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
)

// formats supported for output of various commands
const (
	DefaultFormat      = "txt"
	TextFormat         = "txt"
	JSONFormat         = "json"
	DOTFormat          = "dot"
	CSVFormat          = "csv"
	MDFormat           = "md"
	SVGFormat          = "svg"
	GraphvizExecutable = DOTFormat
)

// WriteToFile generates output to given file
func WriteToFile(output, filePath string) error {
	fp, err := os.Create(filePath)
	if err != nil {
		return err
	}
	_, err = fp.WriteString(output)
	if err != nil {
		return err
	}
	return nil
}

// CheckGraphvizExist checks if "graphviz" executable exists
func CheckGraphvizExist() bool {
	// check if graphviz is installed to continue
	if _, err := exec.LookPath(GraphvizExecutable); err != nil {
		return false
	}
	return true
}

// ValidateOutputFormat returns error if the input format is not in the given list,
// or if the supported format is svg (in the list) but graphviz is not installed.
func ValidateOutputFormat(format string, formats []string) error {
	for _, formatName := range formats {
		if format == formatName {
			if format == SVGFormat { // if format is SVG check also if graphviz is installed,
				// otherwise output can not be produced
				if !CheckGraphvizExist() {
					return errors.New(netpolerrors.GraphvizIsNotFound)
				}
			}
			return nil
		}
	}
	return errors.New(netpolerrors.FormatNotSupportedErrStr(format))
}
