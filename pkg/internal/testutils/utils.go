package testutils

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/netpol-analyzer/pkg/internal/utils"
)

// a flag for writing/overriding the golden result files for tests
var update = flag.Bool("update", false, "write or override golden files")

const (
	dirLevelUp            = ".."
	testsDirName          = "tests"
	standardPkgLevelDepth = 3 // e.g. pkg/netpol/connlist
	internalPkgLevelDepth = 5 // e.g. pkg/netpol/connlist/internal/ingressanalyzer
)

func GetTestsDir() string {
	return GetTestsDirWithDepth(standardPkgLevelDepth)
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

// GetDebugMsgWithTestNameAndFormat: testing helping func - writes debug message for good path tests
func GetDebugMsgWithTestNameAndFormat(testName, format string) string {
	return fmt.Sprintf("test: %q, output format: %q", testName, format)
}

// CheckActualVsExpectedOutputMatch: testing helping func - checks if actual output matches expected output,
// if not generates actual output file
// if --update flag is on, writes the actual output to the expected output file
func CheckActualVsExpectedOutputMatch(t *testing.T, testName, dirName, expectedOutputFileName, actualOutput, testInfo string) {
	expectedOutputFile := filepath.Join(GetTestsDir(), dirName, expectedOutputFileName)
	// if the --update flag is on (then generate/ override the expected output file with the actualOutput)
	if *update {
		err := utils.WriteToFile(actualOutput, expectedOutputFile)
		require.Nil(t, err, testInfo)
		return
	}
	// read expected output file
	expectedOutput, err := os.ReadFile(expectedOutputFile)
	require.Nil(t, err, testInfo)
	actualOutputFileName := "actual_" + expectedOutputFileName
	actualOutputFile := filepath.Join(GetTestsDir(), dirName, actualOutputFileName)
	if cleanStr(string(expectedOutput)) != cleanStr(actualOutput) {
		err := utils.WriteToFile(actualOutput, actualOutputFile)
		require.Nil(t, err, testInfo)
	}
	require.Equal(t, cleanStr(string(expectedOutput)), cleanStr(actualOutput),
		"output mismatch for %s, actual output file %q vs expected output file: %q",
		testInfo,
		actualOutputFile, expectedOutputFile)
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
