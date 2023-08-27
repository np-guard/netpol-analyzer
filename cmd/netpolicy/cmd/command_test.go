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

// check that expected is the same as actual
func sameOutput(t *testing.T, actual, expected, testName string, isFile bool) {
	assert.Equal(t, expected, actual, "error - unexpected output for test %s, isFile: %d", testName, isFile)
}

// check that expected is contained in actual
func containedOutput(t *testing.T, actual, expected, testName string, isFile bool) {
	isContained := strings.Contains(actual, expected)
	assert.True(t, isContained, "test %s error: %s not contained in %s, isFile: %d", testName, expected, actual, isFile)
}

func clean(test cmdTest) {
	if test.hasFile {
		os.Remove(outFileName)
	}
}

func runTest(test cmdTest, t *testing.T) {
	// run the test and get its output
	preTestRun()
	rootCmd := newCommandRoot()
	rootCmd.SetArgs(test.args)
	err := rootCmd.Execute()
	if !test.isErr {
		require.Nilf(t, err, "expected no errors, but got %v", err)
	} else {
		require.NotNil(t, err, "expected error, but got no error")
	}
	actual := postTestRun(test.isErr)

	// check if has file and if it exists
	var fileContent []byte
	if test.hasFile {
		_, err := os.Stat(outFileName)
		require.Nil(t, err)
		fileContent, err = os.ReadFile(outFileName)
		require.Nil(t, err)
	}

	// compare actual to test.expectedOutput
	if test.exact {
		sameOutput(t, actual, test.expectedOutput, test.name, false)
		if test.hasFile {
			sameOutput(t, string(fileContent), test.expectedOutput, test.name, true)
		}
		return
	}

	if test.containment {
		containedOutput(t, actual, test.expectedOutput, test.name, false)
		if test.hasFile {
			containedOutput(t, string(fileContent), test.expectedOutput, test.name, true)
		}
		return
	}

	assert.Error(t, errors.New(""), "test %s: missing containment or equality flag for test")
}

type cmdTest struct {
	name           string
	args           []string
	expectedOutput string
	exact          bool
	containment    bool
	isErr          bool
	hasFile        bool
}

const outFileName = "test_out.txt"

func TestCommands(t *testing.T) {
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
			name:           "test_illegal_diff_no_args",
			args:           []string{"diff"},
			expectedOutput: "both directory paths dir1 and dir2 are required",
			containment:    true,
			isErr:          true,
		},
		{
			name:           "test_illegal_diff_unsupported_args",
			args:           []string{"diff", "--dirpath", filepath.Join(getTestsDir(), "onlineboutique")},
			expectedOutput: "dirpath flag is not used with diff command",
			containment:    true,
			isErr:          true,
		},
		{
			name: "test_illegal_diff_output_format",
			args: []string{
				"diff",
				"--dir1",
				filepath.Join(getTestsDir(), "onlineboutique_workloads"),
				"--dir2",
				filepath.Join(getTestsDir(), "onlineboutique_workloads_changed_workloads"),
				"-o",
				"png"},
			expectedOutput: "png output format is not supported.",
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

		{
			name: "test_legal_list_with_out_file",
			args: []string{
				"list",
				"--dirpath",
				filepath.Join(getTestsDir(), "onlineboutique"),
				"-f",
				outFileName,
			},
			expectedOutput: testLegalListOutput,
			exact:          true,
			isErr:          false,
			hasFile:        true,
		},

		{
			name: "test_legal_list_with_focus_workload",
			args: []string{
				"list",
				"--dirpath",
				filepath.Join(getTestsDir(), "onlineboutique_workloads"),
				"--focusworkload",
				"emailservice",
			},
			expectedOutput: "default/checkoutservice[Deployment] => default/emailservice[Deployment] : TCP 8080",
			exact:          true,
			isErr:          false,
		},
		{
			name: "test_legal_list_with_focus_workload_format_of_ns_and_name",
			args: []string{
				"list",
				"--dirpath",
				filepath.Join(getTestsDir(), "onlineboutique_workloads"),
				"--focusworkload",
				"default/emailservice",
			},
			expectedOutput: "default/checkoutservice[Deployment] => default/emailservice[Deployment] : TCP 8080",
			exact:          true,
			isErr:          false,
		},
		{
			name: "test_legal_list_with_focus_workload_of_ingress_controller",
			args: []string{
				"list",
				"--dirpath",
				filepath.Join(getTestsDir(), "acs-security-demos"),
				"--focusworkload",
				"ingress-controller",
			},
			expectedOutput: "{ingress-controller} => frontend/asset-cache[Deployment] : TCP 8080\n" +
				"{ingress-controller} => frontend/webapp[Deployment] : TCP 8080",
			exact: true,
			isErr: false,
		},
		{
			name: "test_legal_list_with_focus_workload_json_output",
			args: []string{
				"list",
				"--dirpath",
				filepath.Join(getTestsDir(), "onlineboutique_workloads"),
				"--focusworkload",
				"emailservice",
				"--output",
				"json",
			},
			expectedOutput: "[\n" +
				"  {\n" +
				"    \"src\": \"default/checkoutservice[Deployment]\",\n" +
				"    \"dst\": \"default/emailservice[Deployment]\",\n" +
				"    \"conn\": \"TCP 8080\"\n" +
				"  }\n" +
				"]",
			exact: true,
			isErr: false,
		},

		{
			name: "test_illegal_list_output_format",
			args: []string{
				"list",
				"--dirpath",
				filepath.Join(getTestsDir(), "onlineboutique"),
				"-o",
				"png"},
			expectedOutput: "png output format is not supported.",
			containment:    true,
			isErr:          true,
		},

		{
			name: "test_legal_list_with_focus_workload_dot_output",
			args: []string{
				"list",
				"--dirpath",
				filepath.Join(getTestsDir(), "onlineboutique_workloads"),
				"--focusworkload",
				"emailservice",
				"--output",
				"dot",
			},
			expectedOutput: "digraph {\n" +
				"\t\"default/checkoutservice[Deployment]\" [label=\"default/checkoutservice[Deployment]\" color=\"blue\" fontcolor=\"blue\"]\n" +
				"\t\"default/emailservice[Deployment]\" [label=\"default/emailservice[Deployment]\" color=\"blue\" fontcolor=\"blue\"]\n" +
				"\t\"default/checkoutservice[Deployment]\" -> \"default/emailservice[Deployment]\"" +
				" [label=\"TCP 8080\" color=\"gold2\" fontcolor=\"darkgreen\"]\n" +
				"}",
			exact: true,
			isErr: false,
		},

		{
			name: "test_legal_list_with_focus_workload_csv_output",
			args: []string{
				"list",
				"--dirpath",
				filepath.Join(getTestsDir(), "onlineboutique_workloads"),
				"--focusworkload",
				"emailservice",
				"--output",
				"csv",
			},
			expectedOutput: "src,dst,conn\n" +
				"default/checkoutservice[Deployment],default/emailservice[Deployment],TCP 8080\n",
			exact: true,
			isErr: false,
		},

		{
			name: "test_legal_list_with_focus_workload_md_output",
			args: []string{
				"list",
				"--dirpath",
				filepath.Join(getTestsDir(), "onlineboutique_workloads"),
				"--focusworkload",
				"emailservice",
				"--output",
				"md",
			},
			expectedOutput: "| src | dst | conn |\n" +
				"|-----|-----|------|\n" +
				"| default/checkoutservice[Deployment] | default/emailservice[Deployment] | TCP 8080 |",
			exact: true,
			isErr: false,
		},
		{
			name: "test_illegal_use_of_quiet_and_verbose_flags",
			args: []string{
				"list",
				"--dirpath",
				filepath.Join(getTestsDir(), "onlineboutique_workloads"),
				"-q",
				"-v",
			},
			expectedOutput: "-q and -v cannot be specified together",
			containment:    true,
			isErr:          true,
		},
		{
			name: "test_legal_diff_txt_output",
			args: []string{
				"diff",
				"--dir1",
				filepath.Join(getTestsDir(), "onlineboutique_workloads"),
				"--dir2",
				filepath.Join(getTestsDir(), "onlineboutique_workloads_changed_workloads"),
				"--output",
				"txt",
			},
			expectedOutput: "Connectivity diff:\n" +
				"diff-type: added, source: 0.0.0.0-255.255.255.255, destination: default/unicorn[Deployment], dir1:" +
				"  No Connections, dir2: All Connections, workloads-diff-info: workload default/unicorn[Deployment] added\n" +
				"diff-type: added, source: default/redis-cart[Deployment], destination: default/unicorn[Deployment], dir1:" +
				"  No Connections, dir2: All Connections, workloads-diff-info: workload default/unicorn[Deployment] added\n" +
				"diff-type: added, source: default/unicorn[Deployment], destination: 0.0.0.0-255.255.255.255, dir1:" +
				"  No Connections, dir2: All Connections, workloads-diff-info: workload default/unicorn[Deployment] added\n" +
				"diff-type: added, source: default/unicorn[Deployment], destination: default/redis-cart[Deployment], dir1:" +
				"  No Connections, dir2: All Connections, workloads-diff-info: workload default/unicorn[Deployment] added",
			exact: true,
			isErr: false,
		},
		{
			name: "test_legal_diff_txt_output_with_file",
			args: []string{
				"diff",
				"--dir1",
				filepath.Join(getTestsDir(), "onlineboutique_workloads"),
				"--dir2",
				filepath.Join(getTestsDir(), "onlineboutique_workloads_changed_workloads"),
				"--output",
				"txt",
				"-f",
				outFileName,
			},
			expectedOutput: "Connectivity diff:\n" +
				"diff-type: added, source: 0.0.0.0-255.255.255.255, destination: default/unicorn[Deployment], dir1:" +
				"  No Connections, dir2: All Connections, workloads-diff-info: workload default/unicorn[Deployment] added\n" +
				"diff-type: added, source: default/redis-cart[Deployment], destination: default/unicorn[Deployment], dir1:" +
				"  No Connections, dir2: All Connections, workloads-diff-info: workload default/unicorn[Deployment] added\n" +
				"diff-type: added, source: default/unicorn[Deployment], destination: 0.0.0.0-255.255.255.255, dir1:" +
				"  No Connections, dir2: All Connections, workloads-diff-info: workload default/unicorn[Deployment] added\n" +
				"diff-type: added, source: default/unicorn[Deployment], destination: default/redis-cart[Deployment], dir1:" +
				"  No Connections, dir2: All Connections, workloads-diff-info: workload default/unicorn[Deployment] added",
			exact:   true,
			isErr:   false,
			hasFile: true,
		},
		{
			name: "test_legal_diff_csv_output",
			args: []string{
				"diff",
				"--dir1",
				filepath.Join(getTestsDir(), "onlineboutique_workloads"),
				"--dir2",
				filepath.Join(getTestsDir(), "onlineboutique_workloads_changed_workloads"),
				"--output",
				"csv",
			},
			expectedOutput: "diff-type,source,destination,dir1,dir2,workloads-diff-info\n" +
				"added,0.0.0.0-255.255.255.255,default/unicorn[Deployment],No Connections,All Connections," +
				"workload default/unicorn[Deployment] added\n" +
				"added,default/redis-cart[Deployment],default/unicorn[Deployment],No Connections,All Connections," +
				"workload default/unicorn[Deployment] added\n" +
				"added,default/unicorn[Deployment],0.0.0.0-255.255.255.255,No Connections,All Connections," +
				"workload default/unicorn[Deployment] added\n" +
				"added,default/unicorn[Deployment],default/redis-cart[Deployment],No Connections,All Connections," +
				"workload default/unicorn[Deployment] added\n" +
				"",
			exact: true,
			isErr: false,
		},
		{
			name: "test_legal_diff_md_output",
			args: []string{
				"diff",
				"--dir1",
				filepath.Join(getTestsDir(), "onlineboutique_workloads"),
				"--dir2",
				filepath.Join(getTestsDir(), "onlineboutique_workloads_changed_workloads"),
				"--output",
				"md",
			},
			expectedOutput: "| diff-type | source | destination | dir1 | dir2 | workloads-diff-info |\n" +
				"|-----------|--------|-------------|------|------|---------------------|\n" +
				"| added | 0.0.0.0-255.255.255.255 | default/unicorn[Deployment] | No Connections " +
				"| All Connections | workload default/unicorn[Deployment] added |\n" +
				"| added | default/redis-cart[Deployment] | default/unicorn[Deployment] | No Connections " +
				"| All Connections | workload default/unicorn[Deployment] added |\n" +
				"| added | default/unicorn[Deployment] | 0.0.0.0-255.255.255.255 | No Connections " +
				"| All Connections | workload default/unicorn[Deployment] added |\n" +
				"| added | default/unicorn[Deployment] | default/redis-cart[Deployment] | No Connections " +
				"| All Connections | workload default/unicorn[Deployment] added |",
			exact: true,
			isErr: false,
		},
	}

	for _, test := range tests {
		runTest(test, t)
		clean(test)
	}
}

func getTestsDir() string {
	currentDir, _ := os.Getwd()
	res := filepath.Join(currentDir, "..", "..", "..", "tests")
	return res
}
