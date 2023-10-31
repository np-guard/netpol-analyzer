package cmd

import (
	_ "embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	stdoutFile *os.File
	testOutR   *os.File
	testOutW   *os.File
)

const outFileName = "test_out.txt"
const defaultFormat = "txt"

// redirect command's execute stdout to a pipe
func preTestRun() {
	stdoutFile = os.Stdout
	testOutR, testOutW, _ = os.Pipe()
	os.Stdout = testOutW
}

// finalize test's command execute and get its output
func postTestRun() string {
	testOutW.Close()
	out, _ := io.ReadAll(testOutR)
	os.Stdout = stdoutFile
	return string(out)
}

// get 'tests' directory path
func getTestsDir() string {
	currentDir, _ := os.Getwd()
	res := filepath.Join(currentDir, "..", "..", "..", "tests")
	return res
}

// build a new command with args list and execute it, returns the actual output from stdout and the execute err if exists
func buildAndExecuteCommand(args []string) (string, error) {
	preTestRun()
	cmd := newCommandRoot()
	cmd.SetArgs(args)
	err := cmd.Execute()
	actualOut := postTestRun()
	return actualOut, err
}

// append the optional args of a command if the values are not empty
func addCmdOptionalArgs(format, outputFile, focusWorkload string) []string {
	res := []string{}
	if focusWorkload != "" {
		res = append(res, "--focusworkload", focusWorkload)
	}
	if format != "" {
		res = append(res, "--output", format)
	}
	if outputFile != "" {
		res = append(res, "-f", outputFile)
	}
	return res
}

// compares actual vs expected output
func compareActualVsExpectedOutput(t *testing.T, dir, testName, expectedOutputFileName, actualOutput, outputFile string) {
	expectedOutputFile := filepath.Join(getTestsDir(), dir, expectedOutputFileName)
	expectedOutput, err := os.ReadFile(expectedOutputFile)
	require.Nil(t, err)
	actualOutputFileName := "actual_" + expectedOutputFileName
	actualOutputFile := filepath.Join(getTestsDir(), dir, actualOutputFileName)
	if string(expectedOutput) != actualOutput {
		// generate actual file for self check
		err := writeBufToFile(actualOutputFile, expectedOutput)
		require.Nil(t, err, "test: %q", testName)
	}
	require.Equal(t, string(expectedOutput), actualOutput,
		"output mismatch for test %q, actual output file %q vs expected output file: %q",
		testName, actualOutputFile, expectedOutputFile)
	if outputFile != "" {
		_, err := os.Stat(outputFile)
		require.Nil(t, err, "test: %q", testName)
		fileContent, err := os.ReadFile(outputFile)
		require.Nil(t, err, "test: %q", testName)
		require.Equal(t, string(expectedOutput), string(fileContent),
			"output mismatch for test %q, actual output file %q vs expected output file: %q", testName, outputFile, expectedOutputFile)
		os.Remove(outputFile)
	}
}

// composes test name from list command test's args
func getListCommandTestNameFromArgs(dirName, focusWorkload, format string) string {
	testName := "dir_" + dirName
	if focusWorkload != "" {
		testName += "_focus_workload_" + focusWorkload
	}
	if format != "" {
		testName += "_in_" + format
	}
	return testName
}

// determines the file suffix from the format
func determineFileSuffix(format string) string {
	fileSuffix := defaultFormat
	if format != "" {
		fileSuffix = format
	}
	return fileSuffix
}

// gets the name of expected output file for a list command from its args
func getListCmdExpectedOutputFile(focusWorkload, format string) string {
	fileSuffix := determineFileSuffix(format)
	fileName := "connlist_output." + fileSuffix
	if focusWorkload != "" {
		fileName = focusWorkload + "_" + fileName
	}
	return fileName
}

func getDiffCmdExpectedOutputFile(dir1, format string) string {
	return "diff_output_from_" + dir1 + "." + determineFileSuffix(format)
}

// TestCommandsFailExecute - tests executing failure for illegal commands or commands with invalid args or with wrong input values
func TestCommandsFailExecute(t *testing.T) {
	tests := []struct {
		name                  string
		args                  []string
		expectedErrorContains string
	}{
		{
			name:                  "unknown_command_should_return_error_of_unknown_command_for_k8snetpolicy",
			args:                  []string{"A"},
			expectedErrorContains: "unknown command \"A\" for \"k8snetpolicy\"",
		},
		{
			name:                  "eval_command_with_no_args_is_illegal_should_return_error_of_undefined_source",
			args:                  []string{"eval"},
			expectedErrorContains: "no source defined",
		},
		{
			name:                  "diff_command_with_no_args_is_illegal_should_return_error_there_are_required_flags",
			args:                  []string{"diff"},
			expectedErrorContains: "both directory paths dir1 and dir2 are required",
		},
		{
			name:                  "diff_command_args_contain_dirpath_should_return_error_of_unsupported_flag",
			args:                  []string{"diff", "--dirpath", filepath.Join(getTestsDir(), "onlineboutique")},
			expectedErrorContains: "dirpath flag is not used with diff command",
		},
		{
			name: "diff_command_with_unsupported_output_format_should_return_error",
			args: []string{
				"diff",
				"--dir1",
				filepath.Join(getTestsDir(), "onlineboutique_workloads"),
				"--dir2",
				filepath.Join(getTestsDir(), "onlineboutique_workloads_changed_workloads"),
				"-o",
				"png"},
			expectedErrorContains: "png output format is not supported.",
		},
		{
			name: "eval_command_with_not_existing_peer_should_return_error_not_found_peer",
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
			expectedErrorContains: "could not find peer default/default/adservice-77d5cd745d",
		},
		{
			name: "list_command_with_unsupported_output_format_should_return_error",
			args: []string{
				"list",
				"--dirpath",
				filepath.Join(getTestsDir(), "onlineboutique"),
				"-o",
				"png"},
			expectedErrorContains: "png output format is not supported.",
		},
		{
			name: "test_using_q_and_v_verbosity_flags_together_should_return_an_error_of_illegal_use_of_quiet_and_verbose_flags",
			args: []string{
				"list",
				"--dirpath",
				filepath.Join(getTestsDir(), "onlineboutique_workloads"),
				"-q",
				"-v",
			},
			expectedErrorContains: "-q and -v cannot be specified together",
		},
		{
			name: "eval_command_on_dir_with_severe_error_wit_fail_flag_stops_executing_and_returns_the_severe_err_as_err",
			args: []string{
				"eval",
				"--dirpath",
				filepath.Join(getTestsDir(), "onlineboutique_with_pods_severe_error"),
				"-s",
				"adservice-77d5cd745d-t8mx4",
				"-d",
				"emailservice-54c7c5d9d-vp27n",
				"-p",
				"80",
				"--fail"},
			expectedErrorContains: "had processing errors: YAML document is malformed",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildAndExecuteCommand(tt.args)
			require.Contains(t, err.Error(), tt.expectedErrorContains,
				"error mismatch for test %q, actual: %q, expected contains: %q", tt.name, err.Error(), tt.expectedErrorContains)
		})
	}
}

// TestListCommandOutput tests the output of legal list command
func TestListCommandOutput(t *testing.T) {
	cases := []struct {
		dirName       string
		focusWorkload string
		format        string
		outputFile    string
	}{
		// when focusWorkload is empty, output should be the connlist of the dir
		// when format is empty - output should be in defaultFormat (txt)
		// when outputFile is empty - output should be written to stout only
		{
			dirName: "onlineboutique",
		},
		{
			dirName:       "onlineboutique_workloads",
			focusWorkload: "emailservice",
		},
		{
			dirName:       "onlineboutique_workloads",
			focusWorkload: "default/emailservice",
		},
		{
			dirName:       "acs-security-demos",
			focusWorkload: "ingress-controller",
		},
		{
			dirName:       "onlineboutique_workloads",
			focusWorkload: "emailservice",
			format:        "json",
		},
		{
			dirName:       "onlineboutique_workloads",
			focusWorkload: "emailservice",
			format:        "dot",
		},
		{
			dirName:       "onlineboutique_workloads",
			focusWorkload: "emailservice",
			format:        "csv",
		},
		{
			dirName:       "onlineboutique_workloads",
			focusWorkload: "emailservice",
			format:        "md",
		},
		{
			// the test contains malformed yaml beside to legal yaml.
			//  MalformedYamlDocError is not fatal, thus not returned
			// analysis is able to parse some deployments, thus can produce connectivity output
			dirName: filepath.Join("bad_yamls", "document_with_syntax_error"),
		},
		{
			dirName:    "onlineboutique",
			outputFile: outFileName,
		},
	}
	for _, tt := range cases {
		tt := tt
		focusWorkloadStr := strings.Replace(tt.focusWorkload, "/", "_", 1)
		testName := getListCommandTestNameFromArgs(tt.dirName, focusWorkloadStr, tt.format)
		t.Run(testName, func(t *testing.T) {
			args := []string{"list", "--dirpath", filepath.Join(getTestsDir(), tt.dirName)}
			args = append(args, addCmdOptionalArgs(tt.format, tt.outputFile, tt.focusWorkload)...)
			actualOut, err := buildAndExecuteCommand(args)
			require.Nil(t, err, "test: %q", testName)
			expectedOutputFileName := getListCmdExpectedOutputFile(focusWorkloadStr, tt.format)
			compareActualVsExpectedOutput(t, tt.dirName, testName, expectedOutputFileName, actualOut, tt.outputFile)
		})
	}
}

// TestDiffCommandOutput tests the output of legal diff command
func TestDiffCommandOutput(t *testing.T) {
	cases := []struct {
		dir1       string
		dir2       string
		format     string
		outputFile string
	}{
		{
			dir1:   "onlineboutique_workloads",
			dir2:   "onlineboutique_workloads_changed_workloads",
			format: "txt",
		},
		{
			dir1:   "onlineboutique_workloads",
			dir2:   "onlineboutique_workloads_changed_workloads",
			format: "csv",
		},
		{
			dir1:   "onlineboutique_workloads",
			dir2:   "onlineboutique_workloads_changed_workloads",
			format: "md",
		},
		{
			// when format is empty - output should be in defaultFormat (txt)
			dir1: "onlineboutique",
			dir2: "onlineboutique_with_pods_severe_error",
		},
		{
			dir1:       "onlineboutique_workloads",
			dir2:       "onlineboutique_workloads_changed_workloads",
			format:     "txt",
			outputFile: outFileName,
		},
	}
	for _, tt := range cases {
		tt := tt
		testName := ""
		if tt.format != "" {
			testName = tt.format + "_"
		}
		testName += "diff_between_" + tt.dir2 + "_and_" + tt.dir1
		t.Run(testName, func(t *testing.T) {
			args := []string{"diff", "--dir1", filepath.Join(getTestsDir(), tt.dir1), "--dir2", filepath.Join(getTestsDir(), tt.dir2)}
			args = append(args, addCmdOptionalArgs(tt.format, tt.outputFile, "")...)
			actualOut, err := buildAndExecuteCommand(args)
			require.Nil(t, err, "test: %q", testName)
			expectedOutputFileName := getDiffCmdExpectedOutputFile(tt.dir1, tt.format)
			compareActualVsExpectedOutput(t, tt.dir2, testName, expectedOutputFileName, actualOut, tt.outputFile)
		})
	}
}

// TestEvalCommandOutput tests the output of legal eval command
func TestEvalCommandOutput(t *testing.T) {
	cases := []struct {
		dir        string
		sourcePod  string
		destPod    string
		port       string
		evalResult bool
	}{
		{
			dir:        "onlineboutique",
			sourcePod:  "adservice-77d5cd745d-t8mx4",
			destPod:    "emailservice-54c7c5d9d-vp27n",
			port:       "80",
			evalResult: false,
		},
		{
			dir:        "onlineboutique_with_pods_severe_error",
			sourcePod:  "adservice-77d5cd745d-t8mx4",
			destPod:    "emailservice-54c7c5d9d-vp27n",
			port:       "80",
			evalResult: false,
		},
	}
	for _, tt := range cases {
		tt := tt
		testName := "eval_" + tt.dir + "_from_" + tt.sourcePod + "_to_" + tt.destPod
		t.Run(testName, func(t *testing.T) {
			args := []string{"eval", "--dirpath", filepath.Join(getTestsDir(), tt.dir), "-s", tt.sourcePod, "-d", tt.destPod, "-p", tt.port}
			actualOut, err := buildAndExecuteCommand(args)
			require.Nil(t, err, "test: %q", testName)
			require.Contains(t, actualOut, fmt.Sprintf("%v", tt.evalResult),
				"unexpected result for test %q, should be %v", testName, tt.evalResult)
		})
	}
}

// TestCommandWithFailFlag testing list or diff commands with --fail flag
// if there are severe errors on any input dir, command run should stop and return empty result
func TestCommandWithFailFlag(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{
			name: "diff_command_with_fail_flag_one_dir_with_severe_error_should_return_empty_output",
			args: []string{
				"diff",
				"--dir1",
				filepath.Join(getTestsDir(), "onlineboutique"),
				"--dir2",
				filepath.Join(getTestsDir(), "onlineboutique_with_pods_severe_error"),
				"--fail"},
		},
		{
			name: "list_cmd_dir_with_severe_error_running_with_fail_stops_and_return_empty_output",
			//  MalformedYamlDocError is not fatal, but severe, thus stops the run if --fail is on
			// as we saw in a previous test on same path, when --fail is not used, the test produces connectivity map
			args: []string{
				"list",
				"--dirpath",
				filepath.Join(getTestsDir(), "bad_yamls", "document_with_syntax_error"),
				"--fail",
			},
		},
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			actualOut, _ := buildAndExecuteCommand(tt.args)
			require.Empty(t, actualOut, "unexpected result for test %q, should be empty", tt.name)
		})
	}
}
