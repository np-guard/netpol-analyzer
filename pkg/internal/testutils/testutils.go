package testutils

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/netpol-analyzer/pkg/internal/output"
)

// a flag for writing/overriding the golden result files for tests
var update = flag.Bool("update", false, "write or override golden files")

const (
	dirLevelUp                           = ".."
	testsDirName                         = "tests"
	connlistExpectedOutputFileNamePrefix = "connlist_output."
	StandardPkgLevelDepth                = 3 // e.g. pkg/netpol/connlist
	internalPkgLevelDepth                = 5 // e.g. pkg/netpol/connlist/internal/ingressanalyzer
	underscore                           = "_"
	formatStr                            = "_format_"
)

func GetTestsDir() string {
	return GetTestsDirWithDepth(StandardPkgLevelDepth)
}

func GetTestsDirFromInternalPkg() string {
	return GetTestsDirWithDepth(internalPkgLevelDepth)
}

func GetTestsDirWithDepth(depth int) string {
	res, _ := os.Getwd()
	for i := 0; i < depth; i++ {
		res = filepath.Join(res, dirLevelUp)
	}
	return filepath.Join(res, testsDirName)
}

// ConnlistTestNameByTestType returns connlist test name and test's expected output file from some tests args
func ConnlistTestNameByTestType(dirName, focusWorkload, format string) (testName, expectedOutputFileName string) {
	switch {
	case focusWorkload == "":
		return dirName + formatStr + format, connlistExpectedOutputFileNamePrefix + format

	case focusWorkload != "":
		focusWorkloadStr := strings.Replace(focusWorkload, "/", underscore, 1)
		return dirName + "_focus_workload_" + focusWorkloadStr + formatStr + format,
			focusWorkloadStr + underscore + connlistExpectedOutputFileNamePrefix + format
	}
	return "", ""
}

// DiffTestName returns diff test name from the names of the sources
func DiffTestName(ref1, ref2 string) string {
	return "diff_between_" + ref2 + "_and_" + ref1
}

// CheckActualVsExpectedOutputMatch: testing helping func - checks if actual output matches expected output,
// if not generates actual output file
// if --update flag is on, writes the actual output to the expected output file
func CheckActualVsExpectedOutputMatch(t *testing.T, dirName, expectedOutputFileName, actualOutput, testInfo, outFile string,
	currDirDepth int, specialOutputFilePath bool) {
	expectedOutputFile := filepath.Join(GetTestsDirWithDepth(currDirDepth), dirName, expectedOutputFileName)
	if specialOutputFilePath { // expected output file is given as a path (not under test dir)
		expectedOutputFile = expectedOutputFileName
	}
	// if the --update flag is on (then generate/ override the expected output file with the actualOutput)
	if *update {
		err := output.WriteToFile(actualOutput, expectedOutputFile)
		require.Nil(t, err, testInfo)
		return
	}
	// read expected output file
	expectedOutput, err := os.ReadFile(expectedOutputFile)
	require.Nil(t, err, testInfo)
	actualOutputFileName := "actual_" + expectedOutputFileName
	actualOutputFile := filepath.Join(GetTestsDirWithDepth(currDirDepth), dirName, actualOutputFileName)
	if cleanStr(string(expectedOutput)) != cleanStr(actualOutput) {
		err := output.WriteToFile(actualOutput, actualOutputFile)
		require.Nil(t, err, testInfo)
	}
	require.Equal(t, cleanStr(string(expectedOutput)), cleanStr(actualOutput),
		"output mismatch for %s, actual output file %q vs expected output file: %q",
		testInfo,
		actualOutputFile, expectedOutputFile)

	if outFile != "" {
		compareFileContentsVsExpectedOutput(t, testInfo, outFile, string(expectedOutput), expectedOutputFile)
	}
}

// compareFileContentsVsExpectedOutput compares the contents of output file vs expected output
func compareFileContentsVsExpectedOutput(t *testing.T, testInfo, outFile, expectedOutput, expectedOutputFile string) {
	_, err := os.Stat(outFile)
	require.Nil(t, err, testInfo)
	fileContent, err := os.ReadFile(outFile)
	require.Nil(t, err, testInfo)
	require.Equal(t, cleanStr(expectedOutput), cleanStr(string(fileContent)),
		"output mismatch for test %q, actual output file %q vs expected output file: %q", testInfo, outFile, expectedOutputFile)
	os.Remove(outFile)
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
