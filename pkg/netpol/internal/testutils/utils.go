package testutils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/common"
)

const (
	dirLevelUp   = ".."
	testsDirName = "tests"
)

func GetTestsDir() string {
	currentDir, _ := os.Getwd()
	res := filepath.Join(currentDir, dirLevelUp, dirLevelUp, dirLevelUp, testsDirName)
	return res
}

func GetTestsDirFromInternalPkg() string {
	currentDir, _ := os.Getwd()
	res := filepath.Join(currentDir, dirLevelUp, dirLevelUp, dirLevelUp, dirLevelUp, dirLevelUp, testsDirName)
	return res
}

// GetDebugMsgWithTestNameAndFormat: testing helping func - writes debug message for good path tests
func GetDebugMsgWithTestNameAndFormat(testName, format string) string {
	return fmt.Sprintf("test: %q, output format: %q", testName, format)
}

// CheckActualVsExpectedOutputMatch: testing helping func - checks if actual output matches expected output,
// if not generates actual output file
func CheckActualVsExpectedOutputMatch(t *testing.T, testName, dirName, expectedOutputFileName, actualOutput, format string) {
	actualOutputFileName := "actual_" + expectedOutputFileName
	// read expected output file
	expectedOutputFile := filepath.Join(GetTestsDir(), dirName, expectedOutputFileName)
	expectedOutput, err := os.ReadFile(expectedOutputFile)
	require.Nil(t, err, GetDebugMsgWithTestNameAndFormat(testName, format))
	actualOutputFile := filepath.Join(GetTestsDir(), dirName, actualOutputFileName)
	if cleanStr(string(expectedOutput)) != cleanStr(actualOutput) {
		err := common.WriteToFile(actualOutput, actualOutputFile)
		require.Nil(t, err, GetDebugMsgWithTestNameAndFormat(testName, format))
	}
	require.Equal(t, cleanStr(string(expectedOutput)), cleanStr(actualOutput), "output mismatch for %s, actual output file %q vs expected output file: %q",
		GetDebugMsgWithTestNameAndFormat(testName, format),
		actualOutputFile, expectedOutputFile)
}

func cleanStr(str string) string {
	return strings.ReplaceAll(strings.ReplaceAll(str, "\n", ""), "\r", "")
}

// CheckErrorContainment: helping func - if the actual error/warning message does not contain the expected error,
// fail the test with relevant info
func CheckErrorContainment(t *testing.T, testName, expectedErrorMsg, actualErrMsg string, isErr bool) {
	errType := "error"
	if !isErr {
		errType = "warning"
	}
	require.Contains(t, actualErrMsg, expectedErrorMsg, "%s message mismatch for test %q, actual: %q, expected contains: %q",
		errType, testName, actualErrMsg, expectedErrorMsg)
}
