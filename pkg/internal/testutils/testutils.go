/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package testutils

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/netpol-analyzer/pkg/internal/output"
	"github.com/np-guard/netpol-analyzer/pkg/internal/projectpath"
	"github.com/np-guard/netpol-analyzer/pkg/logger"
)

// a flag for writing/overriding the golden result files for tests
var update = flag.Bool("update", false, "write or override golden files")

const (
	connlistExpectedOutputFilePartialName        = "connlist_output."
	explainExpectedOutputFilePartialName         = "explain_output."
	explainExposureExpectedOutputFilePartialName = "explain_exposure_output."
	exposureExpectedOutputFilePartialName        = "exposure_output."
	Underscore                                   = "_"
	dotSign                                      = "."
	CommaSign                                    = ","
	formatStr                                    = "_format_"
	focusWlAnnotation                            = "_focus_workload_"
	withStr                                      = "_with_"
)

var testsDirPath = filepath.Join(projectpath.Root, "tests")
var testsOutputsDirPath = filepath.Join(projectpath.Root, "test_outputs")

// helping func - returns test's dir path from test's dir name
func GetTestDirPath(dirName string) string {
	return filepath.Join(testsDirPath, dirName)
}

// ConnlistTestNameByTestArgs returns connlist test name and test's expected output file from some tests args
func ConnlistTestNameByTestArgs(dirName, focusWorkload, focusWorkloadPeer, focusDirection, focusConn, format string,
	exposureFlag bool) (testName, expectedOutputFileName string) {
	namePrefix := dirName
	if focusWorkload != "" {
		namePrefix += focusWlAnnotation + strings.ReplaceAll(focusWorkload, "/", Underscore)
		if focusDirection != "" {
			namePrefix += Underscore + focusDirection
		}
		if focusWorkloadPeer != "" {
			namePrefix += withStr + strings.ReplaceAll(focusWorkloadPeer, "/", Underscore)
		}
	}
	if focusConn != "" {
		namePrefix += Underscore + focusConn
	}
	testName = namePrefix + formatStr + format
	outputPartialName := connlistExpectedOutputFilePartialName
	if exposureFlag {
		outputPartialName = exposureExpectedOutputFilePartialName
	}
	expectedOutputFileName = namePrefix + Underscore + outputPartialName + format
	return testName, expectedOutputFileName
}

// ExplainTestNameByTestArgs returns explain test name and test's expected output file from some tests args
func ExplainTestNameByTestArgs(dirName, focusWorkload, focusWorkloadPeer, focusDirection, focusConn,
	explainOnly string, exposure bool) (testName, expectedOutputFileName string) {
	namePrefix := dirName
	if focusWorkload != "" {
		namePrefix += focusWlAnnotation + strings.ReplaceAll(focusWorkload, "/", Underscore)
		if focusDirection != "" {
			namePrefix += Underscore + focusDirection
		}
		if focusWorkloadPeer != "" {
			namePrefix += withStr + strings.ReplaceAll(focusWorkloadPeer, "/", Underscore)
		}
	}
	if focusConn != "" {
		namePrefix += Underscore + focusConn
	}
	if explainOnly != "" {
		namePrefix += Underscore + explainOnly
	}
	testName = namePrefix
	outputPartialName := explainExpectedOutputFilePartialName
	if exposure {
		outputPartialName = explainExposureExpectedOutputFilePartialName
	}
	expectedOutputFileName = namePrefix + Underscore + outputPartialName + output.TextFormat
	return testName, expectedOutputFileName
}

// DiffTestNameByTestArgs returns diff test name and test's expected output file from some tests args
func DiffTestNameByTestArgs(ref1, ref2, format string) (testName, expectedOutputFileName string) {
	namePrefix := "diff_between_" + ref2 + "_and_" + ref1
	testName = namePrefix + formatStr + format
	expectedOutputFileName = namePrefix + dotSign + format
	return testName, expectedOutputFileName
}

// CheckActualVsExpectedOutputMatch: testing helping func - checks if actual output matches expected output,
// if not generates actual output file
// if --update flag is on, writes the actual output to the expected output file
func CheckActualVsExpectedOutputMatch(t *testing.T, expectedOutputFileName, actualOutput, testInfo, testingPkg string) {
	expectedOutputFile := filepath.Join(testsOutputsDirPath, testingPkg, expectedOutputFileName)
	// if the --update flag is on (then generate/ override the expected output file with the actualOutput)
	if *update {
		err := output.WriteToFile(actualOutput, expectedOutputFile)
		if err != nil {
			warnOnErrorWritingFile(err, expectedOutputFile)
		}
		// if format is dot - generate/ override also png graph file using graphviz program
		if strings.HasSuffix(expectedOutputFile, dotSign+output.DOTFormat) {
			generateGraphFilesIfPossible(expectedOutputFile)
		}
		return
	}
	// if the format is SVG - skip comparing actual vs expected and return
	// this is used only with our testings, we don't have a test running with only SVG format
	// dot format's files (which is the source of the svg graph) are compared
	if strings.HasSuffix(expectedOutputFile, dotSign+output.SVGFormat) {
		return
	}
	// compare actual vs expected
	// read expected output file
	expectedOutput, err := os.ReadFile(expectedOutputFile)
	if err != nil {
		WarnOnErrorReadingFile(err, expectedOutputFile)
	}
	actualOutputFileName := "actual_" + expectedOutputFileName
	actualOutputFile := filepath.Join(testsOutputsDirPath, testingPkg, actualOutputFileName)
	if cleanStr(string(expectedOutput)) != cleanStr(actualOutput) {
		err := output.WriteToFile(actualOutput, actualOutputFile)
		if err != nil {
			warnOnErrorWritingFile(err, actualOutputFile)
		}
	}
	require.Equal(t, cleanStr(string(expectedOutput)), cleanStr(actualOutput),
		"output mismatch for %s, actual output file %q vs expected output file: %q",
		testInfo,
		actualOutputFile, expectedOutputFile)
}

func WarnOnErrorReadingFile(err error, file string) {
	logger.NewDefaultLogger().Warnf("failed reading file %q; os error: %v occurred", file, err)
}

func warnOnErrorWritingFile(err error, file string) {
	logger.NewDefaultLogger().Warnf("failed writing to file %q; unexpected error %v occurred", file, err)
}

func cleanStr(str string) string {
	return strings.ReplaceAll(strings.ReplaceAll(str, "\n", ""), "\r", "")
}

// CheckErrorContainment: helping func - if the actual error/warning message does not contain the expected error,
// fail the test with relevant info
func CheckErrorContainment(t *testing.T, testInfo, expectedErrorMsg, actualErrMsg string) {
	require.Contains(t, actualErrMsg, expectedErrorMsg, "err/warn message mismatch for test: %q, actual: %q, expected contains: %q",
		testInfo, actualErrMsg, expectedErrorMsg)
}

const graphSuffix = "png"

// checks if "graphviz" executable exists, if yes runs a cmd to generate a png graph file from the dot output
func generateGraphFilesIfPossible(dotFilePath string) {
	// check if graphviz is installed to continue
	if !output.CheckGraphvizExist() {
		logger.NewDefaultLogger().Warnf("dot executable of graphviz was not found. Output Graphs will not be generated")
		return
	}
	// generate png file (this png file is generated for the dot format; however svg is a supported output format)
	graphFilePath := dotFilePath + dotSign + graphSuffix
	cmd := exec.Command(output.GraphvizExecutable, dotFilePath, "-T"+graphSuffix, "-o", graphFilePath)
	if err := cmd.Run(); err != nil {
		logger.NewDefaultLogger().Warnf("failed generating %q; unexpected error: %v", graphFilePath, err)
	}
}
