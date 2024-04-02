package cli

import (
	_ "embed"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"

	ioutput "github.com/np-guard/netpol-analyzer/pkg/internal/output"
	"github.com/np-guard/netpol-analyzer/pkg/internal/testutils"
	"github.com/np-guard/netpol-analyzer/pkg/logger"
)

var (
	stdoutFile *os.File
	testOutR   *os.File
	testOutW   *os.File
)

const outFileName = "test_out.txt"
const currentPkg = "cli"

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
func addCmdOptionalArgs(format, outputFile, focusWorkload string, exposure bool) []string {
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
	if exposure {
		res = append(res, "--exposure")
	}
	return res
}

// determines the file suffix from the format
func determineFileSuffix(format string) string {
	fileSuffix := ioutput.DefaultFormat
	if format != "" {
		fileSuffix = format
	}
	return fileSuffix
}

// gets the test name and name of expected output file for a list command from its args
func getListCmdTestNameAndExpectedOutputFile(dirName, focusWorkload, format string, exposureFlag bool) (testName,
	expectedOutputFileName string) {
	fileSuffix := determineFileSuffix(format)
	return testutils.ConnlistTestNameByTestArgs(dirName, focusWorkload, fileSuffix, exposureFlag)
}

func testInfo(testName string) string {
	return fmt.Sprintf("test: %q", testName)
}

// removes the output file generated for commands which run with `-f` flag
func removeOutFile(outputFile string) {
	if outputFile != "" {
		err := os.Remove(outputFile)
		if err != nil {
			logger.NewDefaultLogger().Warnf("file %q was not removed; os error: %v occurred", outputFile, err)
		}
	}
}

// helping func, reads output file contents and compares it with expected output
func checkFileContentVsExpectedOutput(t *testing.T, outputFile, expectedFile, tInfo string) {
	actualOutFromFile, err := os.ReadFile(outputFile)
	if err != nil {
		testutils.WarnOnErrorReadingFile(err, outputFile)
	}
	testutils.CheckActualVsExpectedOutputMatch(t, expectedFile, string(actualOutFromFile), tInfo, currentPkg)
	removeOutFile(outputFile)
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
			expectedErrorContains: netpolerrors.UnknownCommandErr,
		},
		{
			name:                  "eval_command_with_no_args_is_illegal_should_return_error_of_undefined_source",
			args:                  []string{"eval"},
			expectedErrorContains: netpolerrors.NoSourceDefinedErr,
		},
		{
			name:                  "diff_command_with_no_args_is_illegal_should_return_error_there_are_required_flags",
			args:                  []string{"diff"},
			expectedErrorContains: netpolerrors.RequiredFlagsErr,
		},
		{
			name:                  "diff_command_args_contain_dirpath_should_return_error_of_unsupported_flag",
			args:                  []string{"diff", "--dirpath", testutils.GetTestDirPath("onlineboutique")},
			expectedErrorContains: netpolerrors.FlagMisUseErr,
		},
		{
			name: "diff_command_with_unsupported_output_format_should_return_error",
			args: []string{
				"diff",
				"--dir1",
				testutils.GetTestDirPath("onlineboutique_workloads"),
				"--dir2",
				testutils.GetTestDirPath("onlineboutique_workloads_changed_workloads"),
				"-o",
				"png"},
			expectedErrorContains: netpolerrors.FormatNotSupportedErrStr("png"),
		},
		{
			name: "eval_command_with_not_existing_peer_should_return_error_not_found_peer",
			args: []string{
				"eval",
				"--dirpath",
				testutils.GetTestDirPath("onlineboutique"),
				"-s",
				"default/adservice-77d5cd745d-t8mx4",
				"-d",
				"default/emailservice-54c7c5d9d-vp27n",
				"-p",
				"80"},
			expectedErrorContains: netpolerrors.NotFoundPeerErrStr("default/default/adservice-77d5cd745d"),
		},
		{
			name: "list_command_with_unsupported_output_format_should_return_error",
			args: []string{
				"list",
				"--dirpath",
				testutils.GetTestDirPath("onlineboutique"),
				"-o",
				"png"},
			expectedErrorContains: netpolerrors.FormatNotSupportedErrStr("png"),
		},
		{
			name: "test_using_q_and_v_verbosity_flags_together_should_return_an_error_of_illegal_use_of_quiet_and_verbose_flags",
			args: []string{
				"list",
				"--dirpath",
				testutils.GetTestDirPath("onlineboutique_workloads"),
				"-q",
				"-v",
			},
			expectedErrorContains: netpolerrors.VerbosityFlagsMisUseErrStr,
		},
		{
			name: "eval_command_on_dir_with_severe_error_with_fail_flag_stops_executing_and_returns_the_severe_err_as_err",
			args: []string{
				"eval",
				"--dirpath",
				testutils.GetTestDirPath("onlineboutique_with_pods_severe_error"),
				"-s",
				"adservice-77d5cd745d-t8mx4",
				"-d",
				"emailservice-54c7c5d9d-vp27n",
				"-p",
				"80",
				"--fail"},
			expectedErrorContains: netpolerrors.WrongStartCharacterErr,
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
		exposureFlag  bool
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
			format:        ioutput.JSONFormat,
		},
		{
			dirName:       "onlineboutique_workloads",
			focusWorkload: "emailservice",
			format:        ioutput.DOTFormat,
		},
		{
			dirName:       "onlineboutique_workloads",
			focusWorkload: "emailservice",
			format:        ioutput.CSVFormat,
		},
		{
			dirName:       "onlineboutique_workloads",
			focusWorkload: "emailservice",
			format:        ioutput.MDFormat,
		},
		{
			// the test contains malformed yaml beside to legal yaml.
			// analysis is able to parse some deployments, thus can produce connectivity output
			dirName: "document_with_syntax_error",
		},
		{
			dirName:    "onlineboutique",
			outputFile: outFileName,
		},
		{
			dirName:      "acs-security-demos",
			exposureFlag: true,
		},
	}
	for _, tt := range cases {
		tt := tt
		testName, expectedOutputFileName := getListCmdTestNameAndExpectedOutputFile(tt.dirName, tt.focusWorkload, tt.format, tt.exposureFlag)
		t.Run(testName, func(t *testing.T) {
			args := []string{"list", "--dirpath", testutils.GetTestDirPath(tt.dirName)}
			args = append(args, addCmdOptionalArgs(tt.format, tt.outputFile, tt.focusWorkload, tt.exposureFlag)...)
			actualOut, err := buildAndExecuteCommand(args)
			require.Nil(t, err, "test: %q", testName)
			testutils.CheckActualVsExpectedOutputMatch(t, expectedOutputFileName, actualOut, testInfo(testName), currentPkg)
			if tt.outputFile != "" {
				checkFileContentVsExpectedOutput(t, tt.outputFile, expectedOutputFileName, testInfo(testName))
			}
			removeOutFile(tt.outputFile)
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
			format: ioutput.TextFormat,
		},
		{
			dir1:   "onlineboutique_workloads",
			dir2:   "onlineboutique_workloads_changed_workloads",
			format: ioutput.CSVFormat,
		},
		{
			dir1:   "onlineboutique_workloads",
			dir2:   "onlineboutique_workloads_changed_workloads",
			format: ioutput.MDFormat,
		},
		{
			// when format is empty - output should be in defaultFormat (txt)
			dir1: "onlineboutique",
			dir2: "onlineboutique_with_pods_severe_error",
		},
		{
			dir1:       "onlineboutique_workloads",
			dir2:       "onlineboutique_workloads_changed_workloads",
			format:     ioutput.TextFormat,
			outputFile: outFileName,
		},
	}
	for _, tt := range cases {
		tt := tt
		testName, expectedOutputFileName := testutils.DiffTestNameByTestArgs(tt.dir1, tt.dir2, determineFileSuffix(tt.format))
		t.Run(testName, func(t *testing.T) {
			args := []string{"diff", "--dir1", testutils.GetTestDirPath(tt.dir1), "--dir2",
				testutils.GetTestDirPath(tt.dir2)}
			args = append(args, addCmdOptionalArgs(tt.format, tt.outputFile, "", false)...)
			actualOut, err := buildAndExecuteCommand(args)
			require.Nil(t, err, "test: %q", testName)
			testutils.CheckActualVsExpectedOutputMatch(t, expectedOutputFileName, actualOut, testInfo(testName), currentPkg)

			if tt.outputFile != "" {
				checkFileContentVsExpectedOutput(t, tt.outputFile, expectedOutputFileName, testInfo(testName))
			}
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
			args := []string{"eval", "--dirpath", testutils.GetTestDirPath(tt.dir),
				"-s", tt.sourcePod, "-d", tt.destPod, "-p", tt.port}
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
				testutils.GetTestDirPath("onlineboutique"),
				"--dir2",
				testutils.GetTestDirPath("onlineboutique_with_pods_severe_error"),
				"--fail"},
		},
		{
			name: "list_cmd_dir_with_severe_error_running_with_fail_stops_and_return_empty_output",
			// as we saw in a previous test on same path, when --fail is not used, the test produces connectivity map
			args: []string{
				"list",
				"--dirpath",
				testutils.GetTestDirPath("document_with_syntax_error"),
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
