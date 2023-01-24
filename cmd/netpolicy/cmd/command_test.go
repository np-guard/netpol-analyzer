package cmd

import (
	_ "embed"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	stdoutFile *os.File
	stderrFile *os.File
	testOutR   *os.File
	testOutW   *os.File
	testErrR   *os.File
	testErrW   *os.File

	//go:embed tests_outputs/test_legal_list.txt
	testLegalListOutput string
)

func preTestRun() {
	stdoutFile = os.Stdout
	stderrFile = os.Stderr
	testOutR, testOutW, _ = os.Pipe()
	os.Stdout = testOutW
	testErrR, testErrW, _ = os.Pipe()
	os.Stderr = testErrW
}

// finalize test and get its output
func postTestRun(isErr bool) string {
	testOutW.Close()
	testErrW.Close()
	out, _ := io.ReadAll(testOutR)
	errOut, _ := io.ReadAll(testErrR)
	os.Stdout = stdoutFile
	os.Stderr = stderrFile
	actualOutput := string(out)
	actualErr := string(errOut)
	if isErr {
		return actualErr
	}
	return actualOutput
}

func runTest(test cmdTest, t *testing.T) {
	// run the test and get its output
	preTestRun()
	rootCmd.SetArgs(test.args)
	err := rootCmd.Execute()
	if !test.isErr {
		require.Nilf(t, err, "expected no errors, but got %v", err)
	} else {
		require.NotNil(t, err, "expected error, but got no error")
	}
	actual := postTestRun(test.isErr)

	// compare actual to test.expectedOutput
	if test.exact {
		assert.Equal(t, test.expectedOutput, actual, "error - unexpected output")
	} else if test.containment {
		isContained := strings.Contains(actual, test.expectedOutput)
		assert.True(t, isContained, "test %s error: %s not contained in %s", test.name, test.expectedOutput, actual)
	} else {
		assert.Error(t, errors.New(""), "test %s: missing containment or equality flag for test")
	}
}

type cmdTest struct {
	name           string
	args           []string
	expectedOutput string
	exact          bool
	containment    bool
	isErr          bool
}

func TestCommannds(t *testing.T) {
	tests := []cmdTest{
		{
			name:           "test_illegal_command",
			args:           []string{"A"},
			expectedOutput: "Error: unknown command \"A\" for \"k8snetpolicy\"",
			containment:    true,
			isErr:          true,
		},

		{
			name:           "test_illegal_eval_no_args",
			args:           []string{"eval"},
			expectedOutput: "no source defined",
			containment:    true,
			isErr:          true,
		},

		{
			name: "test_illegal_eval_peer_not_found",
			args: []string{
				"eval",
				"--dirpath",
				filepath.Join(getTestsDir(), "onlineboutique"),
				"-s",
				"default/adservice-77d5cd745d-t8mx4",
				"-d",
				"default/emailservice-54c7c5d9d-vp27n",
				"-p",
				"80"},
			expectedOutput: "could not find peer default/default/adservice-77d5cd745d",
			containment:    true,
			isErr:          true,
		},

		{
			name: "test_legal_eval",
			args: []string{
				"eval",
				"--dirpath",
				filepath.Join(getTestsDir(), "onlineboutique"),
				"-s",
				"adservice-77d5cd745d-t8mx4",
				"-d",
				"emailservice-54c7c5d9d-vp27n",
				"-p",
				"80"},
			expectedOutput: "default/adservice-77d5cd745d-t8mx4 => default/emailservice-54c7c5d9d-vp27n over tcp/80: false\n",
			exact:          true,
			isErr:          false,
		},

		{
			name: "test_legal_list",
			args: []string{
				"list",
				"--dirpath",
				filepath.Join(getTestsDir(), "onlineboutique"),
			},
			expectedOutput: testLegalListOutput,
			exact:          true,
			isErr:          false,
		},
	}

	for _, test := range tests {
		runTest(test, t)
	}
}

func getTestsDir() string {
	currentDir, _ := os.Getwd()
	res := filepath.Join(currentDir, "..", "..", "..", "tests")
	return res
}