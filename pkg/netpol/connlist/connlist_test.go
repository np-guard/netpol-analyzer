package connlist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/common"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/testutils"

	"github.com/stretchr/testify/require"
)

const connlistExpectedOutputFileNamePrefix = "connlist_output."
const underscore = "_"

var allFormats = []string{common.TextFormat, common.JSONFormat, common.CSVFormat, common.MDFormat, common.DOTFormat}

// helping func - returns test's dir path from test's dir name
func getDirPathFromDirName(dirName string) string {
	return filepath.Join(testutils.GetTestsDir(), dirName)
}

// helping func - creates ConnlistAnalyzer with desired opts and returns the analyzer with connlist from provided directory
func getConnlistFromDirPathRes(opts []ConnlistAnalyzerOption, dirName string) (*ConnlistAnalyzer, []Peer2PeerConnection, error) {
	analyzer := NewConnlistAnalyzer(opts...)
	res, _, err := analyzer.ConnlistFromDirPath(getDirPathFromDirName(dirName))
	return analyzer, res, err
}

// helping func - creates the analyzer , gets connlist and writes it to string and verifies results
func verifyConnlistAnalyzeOutputVsExpectedOutput(t *testing.T, analyzerOptions []ConnlistAnalyzerOption, dirName,
	expectedOutputFileName, testName string) {
	analyzer, res, err := getConnlistFromDirPathRes(analyzerOptions, dirName)
	require.Nil(t, err, "test: %q", testName)
	output, err := analyzer.ConnectionsListToString(res)
	require.Nil(t, err, "test: %q", testName)
	expectedOutputFile := filepath.Join(getDirPathFromDirName(dirName), expectedOutputFileName)
	expectedOutput, err := os.ReadFile(expectedOutputFile)
	require.Nil(t, err, "test: %q", testName)
	require.Equal(t, string(expectedOutput), output, "test: %q", testName)
}

// helping func - if focus workload is not empty append it to ConnlistAnalyzerOption list
func appendFocusWorkloadOptIfRequired(focusWorkload string) []ConnlistAnalyzerOption {
	analyzerOptions := []ConnlistAnalyzerOption{}
	if focusWorkload != "" {
		analyzerOptions = append(analyzerOptions, WithFocusWorkload(focusWorkload))
	}
	return analyzerOptions
}

// TestConnList tests the output of ConnlistFromDirPath() for valid input resources
func TestConnList(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name          string
		testDirName   string
		outputFormats []string
	}{
		{
			name:          "dir_ipblockstest_output_txt_format",
			testDirName:   "ipblockstest",
			outputFormats: []string{common.TextFormat},
		},
		{
			name:          "dir_onlineboutique_output_json_md_txt_formats",
			testDirName:   "onlineboutique",
			outputFormats: []string{common.JSONFormat, common.MDFormat, common.TextFormat},
		},
		{
			name:          "dir_onlineboutique_workloads_output_csv_dot_txt_formats",
			testDirName:   "onlineboutique_workloads",
			outputFormats: []string{common.CSVFormat, common.DOTFormat, common.TextFormat},
		},
		{
			name:          "dir_minikube_resources_output_txt_format",
			testDirName:   "minikube_resources",
			outputFormats: []string{common.TextFormat},
		},
		{
			name:          "dir_online_boutique_workloads_no_ns_output_txt_format",
			testDirName:   "online_boutique_workloads_no_ns",
			outputFormats: []string{common.TextFormat},
		},
		{
			name:          "dir_core_pods_without_host_ip_output_txt_format",
			testDirName:   "core_pods_without_host_ip",
			outputFormats: []string{common.TextFormat},
		},
		{
			name:          "dir_acs_security_frontend_demos_output_all_valid_formats",
			testDirName:   "acs_security_frontend_demos",
			outputFormats: allFormats,
		},
		{
			name:          "dir_demo_app_with_routes_and_ingress_output_all_valid_formats",
			testDirName:   "demo_app_with_routes_and_ingress",
			outputFormats: allFormats,
		},
		{
			name:          "dir_k8s_ingress_test_output_all_valid_formats",
			testDirName:   "k8s_ingress_test",
			outputFormats: allFormats,
		},
		{
			name:          "dir_multiple_ingress_objects_with_different_ports_output_all_valid_formats",
			testDirName:   "multiple_ingress_objects_with_different_ports",
			outputFormats: allFormats,
		},
		{
			name:          "dir_one_ingress_multiple_ports_output_all_valid_formats",
			testDirName:   "one_ingress_multiple_ports",
			outputFormats: allFormats,
		},
		{
			name:          "dir_one_ingress_multiple_services_output_all_valid_formats",
			testDirName:   "one_ingress_multiple_services",
			outputFormats: allFormats,
		},
		{
			name:          "dir_acs-security-demos_output_all_valid_formats",
			testDirName:   "acs-security-demos",
			outputFormats: allFormats,
		},
		{
			name:          "dir_acs-security-demos-with-netpol-list_output_txt_format",
			testDirName:   "acs-security-demos-with-netpol-list",
			outputFormats: []string{common.TextFormat},
		},
		{
			name:          "dir_test_with_named_ports_output_txt_format",
			testDirName:   "test_with_named_ports",
			outputFormats: []string{common.TextFormat},
		},
		{
			name:          "dir_test_with_named_ports_changed_netpol_output_txt_format",
			testDirName:   "test_with_named_ports_changed_netpol",
			outputFormats: []string{common.TextFormat},
		},
		{
			name:          "dir_netpol-analysis-example-minimal_output_txt_format",
			testDirName:   "netpol-analysis-example-minimal",
			outputFormats: []string{common.TextFormat},
		},
		{
			name:          "dir_with_end_port_example_output_txt_format",
			testDirName:   "with_end_port_example",
			outputFormats: []string{common.TextFormat},
		},
		{
			name:          "dir_with_end_port_example_new_output_txt_format",
			testDirName:   "with_end_port_example_new",
			outputFormats: []string{common.TextFormat},
		},
		{
			name:          "dir_new_online_boutique_output_txt_format",
			testDirName:   "new_online_boutique",
			outputFormats: []string{common.TextFormat},
		},
		{
			name:          "dir_new_online_boutique_synthesis_output_txt_format",
			testDirName:   "new_online_boutique_synthesis",
			outputFormats: []string{common.TextFormat},
		},
		{
			name:          "dir_multiple_topology_resources_1_output_txt_format",
			testDirName:   "multiple_topology_resources_1",
			outputFormats: []string{common.TextFormat},
		},
		{
			name:          "dir_multiple_topology_resources_2_output_txt_format",
			testDirName:   "multiple_topology_resources_2",
			outputFormats: []string{common.TextFormat},
		},
		{
			name:          "dir_multiple_topology_resources_3_output_txt_format",
			testDirName:   "multiple_topology_resources_3",
			outputFormats: []string{common.TextFormat},
		},
		{
			name:          "dir_multiple_topology_resources_4_output_txt_format",
			testDirName:   "multiple_topology_resources_4",
			outputFormats: []string{common.TextFormat},
		},
		{
			name:          "dir_minimal_test_in_ns_output_txt_format",
			testDirName:   "minimal_test_in_ns",
			outputFormats: []string{common.TextFormat},
		},
		{
			name:          "dir_semanticDiff-same-topologies-old1_output_txt_format",
			testDirName:   "semanticDiff-same-topologies-old1",
			outputFormats: []string{common.TextFormat},
		},
		{
			name:          "dir_semanticDiff-same-topologies-old2_output_txt_format",
			testDirName:   "semanticDiff-same-topologies-old2",
			outputFormats: []string{common.TextFormat},
		},
		{
			name:          "dir_semanticDiff-same-topologies-old3_output_txt_format",
			testDirName:   "semanticDiff-same-topologies-old3",
			outputFormats: []string{common.TextFormat},
		},
		{
			name:          "dir_semanticDiff-same-topologies-new1_output_txt_format",
			testDirName:   "semanticDiff-same-topologies-new1",
			outputFormats: []string{common.TextFormat},
		},
		{
			name:          "dir_semanticDiff-same-topologies-new1a_output_txt_format",
			testDirName:   "semanticDiff-same-topologies-new1a",
			outputFormats: []string{common.TextFormat},
		},
		{
			name:          "dir_semanticDiff-same-topologies-new2_output_txt_format",
			testDirName:   "semanticDiff-same-topologies-new2",
			outputFormats: []string{common.TextFormat},
		},
		{
			name:          "dir_semanticDiff-same-topologies-new3_output_txt_format",
			testDirName:   "semanticDiff-same-topologies-new3",
			outputFormats: []string{common.TextFormat},
		},
		{
			name:          "dir_semanticDiff-orig-topologies-no-policy_output_txt_format",
			testDirName:   "semanticDiff-orig-topologies-no-policy",
			outputFormats: []string{common.TextFormat},
		},
		{
			name:          "dir_semanticDiff-orig-topologies-policy-a_output_txt_format",
			testDirName:   "semanticDiff-orig-topologies-policy-a",
			outputFormats: []string{common.TextFormat},
		},
		{
			name:          "dir_semanticDiff-different-topologies-policy-a_output_txt_format",
			testDirName:   "semanticDiff-different-topologies-policy-a",
			outputFormats: []string{common.TextFormat},
		},
		{
			name:          "dir_semanticDiff-different-topologies-policy-b_output_txt_format",
			testDirName:   "semanticDiff-different-topologies-policy-b",
			outputFormats: []string{common.TextFormat},
		},
		{
			name:          "dir_ipblockstest_2_output_txt_format",
			testDirName:   "ipblockstest_2",
			outputFormats: []string{common.TextFormat},
		},
		{
			name:          "dir_ipblockstest_3_output_txt_format",
			testDirName:   "ipblockstest_3",
			outputFormats: []string{common.TextFormat},
		},
		{
			name:          "dir_ipblockstest_4_output_txt_format",
			testDirName:   "ipblockstest_4",
			outputFormats: []string{common.TextFormat},
		},
		{
			name:          "dir_semanticDiff-different-topologies-policy-a-with-ipblock_output_txt_format",
			testDirName:   "semanticDiff-different-topologies-policy-a-with-ipblock",
			outputFormats: []string{common.TextFormat},
		},
		{
			name:          "dir_semanticDiff-different-topologies-policy-b-with-ipblock_output_txt_format",
			testDirName:   "semanticDiff-different-topologies-policy-b-with-ipblock",
			outputFormats: []string{common.TextFormat},
		},
		{
			name:          "dir_test_with_named_ports_changed_netpol_2_output_txt_format",
			testDirName:   "test_with_named_ports_changed_netpol_2",
			outputFormats: []string{common.TextFormat},
		},
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			for _, format := range tt.outputFormats {
				analyzerOpts := []ConnlistAnalyzerOption{WithOutputFormat(format), WithIncludeJSONManifests()}
				expectedOutputFileName := connlistExpectedOutputFileNamePrefix + format
				verifyConnlistAnalyzeOutputVsExpectedOutput(t, analyzerOpts, tt.testDirName, expectedOutputFileName, tt.name)
			}
		})
	}
}

// TestConnListWithFocusWorkload tests the connlist output of ConnlistFromDirPath() for provided existing workload in valid input resources
func TestConnListWithFocusWorkload(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name          string
		dirName       string
		focusWorkload string
	}{
		{
			name:          "dir_onlineboutique_workloads_focus_workload_emailservice",
			dirName:       "onlineboutique_workloads",
			focusWorkload: "emailservice",
		},
		{
			name:          "dir_k8s_ingress_test_focus_workload_details-v1-79f774bdb9",
			dirName:       "k8s_ingress_test",
			focusWorkload: "details-v1-79f774bdb9",
		},
		{
			name:          "dir_acs-security-demos-added-workloads_focus_workload_ns_backend_name_recommendation",
			dirName:       "acs-security-demos-added-workloads",
			focusWorkload: "backend/recommendation",
		},
		{
			name:          "dir_acs-security-demos-added-workloads_focus_workload_asset-cache",
			dirName:       "acs-security-demos-added-workloads",
			focusWorkload: "asset-cache",
		},
		{
			name:          "dir_acs-security-demos-added-workloads_focus_workload_ns_frontend_name_asset-cache",
			dirName:       "acs-security-demos-added-workloads",
			focusWorkload: "frontend/asset-cache",
		},
		{
			name:          "dir_acs-security-demos-added-workloads_focus_workload_ingress-controller",
			dirName:       "acs-security-demos-added-workloads",
			focusWorkload: "ingress-controller",
		},
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			expectedOutputFileName := strings.Replace(tt.focusWorkload, "/", underscore, 1) + underscore + connlistExpectedOutputFileNamePrefix +
				common.DefaultFormat
			analyzerOpts := []ConnlistAnalyzerOption{WithFocusWorkload(tt.focusWorkload)}
			verifyConnlistAnalyzeOutputVsExpectedOutput(t, analyzerOpts, tt.dirName, expectedOutputFileName, tt.name)
		})
	}
}

// TestConnlistAnalyzeFatalErrors tests fatal errors returned while computing the connlist from dirpath
func TestConnlistAnalyzeFatalErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name             string
		dirName          string
		errorStrContains string
	}{
		{
			name:             "Input_dir_has_netpol_with_invalid_cidr_should_return_fatal_error_of_invalid_CIDR_address",
			dirName:          filepath.Join("bad_netpols", "subdir1"),
			errorStrContains: "CIDR error: invalid CIDR address",
		},
		{
			name:             "Input_dir_has_netpol_with_bad_label_key_should_return_fatal_selector_error",
			dirName:          filepath.Join("bad_netpols", "subdir2"),
			errorStrContains: "selector error: key: Invalid value: \"app@b\": name part must consist of alphanumeric characters",
		},
		{
			name:             "Input_dir_has_netpol_with_invalid_rule_peer_should_return_fatal_rule_NetworkPolicyPeer_error",
			dirName:          filepath.Join("bad_netpols", "subdir3"),
			errorStrContains: "rule NetworkPolicyPeer error: cannot have both IPBlock and PodSelector/NamespaceSelector set",
		},
		{
			name:             "Input_dir_has_netpol_with_empty_rule_peer_should_return_fatal_rule_NetworkPolicyPeer_error",
			dirName:          filepath.Join("bad_netpols", "subdir4"),
			errorStrContains: "rule NetworkPolicyPeer error: cannot have empty rule peer",
		},
		{
			name:             "Input_dir_has_netpol_with_named_port_on_ipblock_peer_should_return_fatal_named_port_error",
			dirName:          filepath.Join("bad_netpols", "subdir6"),
			errorStrContains: "named port error: cannot convert named port for an IP destination",
		},
		{
			name:             "Input_dir_does_not_exist_should_return_fatal_error_accessing_directory",
			dirName:          filepath.Join("bad_yamls", "subdir3"),
			errorStrContains: "error accessing directory",
		},
		{
			name:    "Input_dir_has_illegal_podlist_pods_with_same_owner_ref_name_has_different_labels_should_return_fatal_error",
			dirName: "semanticDiff-same-topologies-illegal-podlist",
			errorStrContains: "Input Pod resources are not supported for connectivity analysis. Found Pods of the same owner demo/cog-agents " +
				"but with different set of labels.",
		},
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			analyzerOpts := []ConnlistAnalyzerOption{WithIncludeJSONManifests()}
			_, res, err := getConnlistFromDirPathRes(analyzerOpts, tt.dirName)
			require.Empty(t, res, "test: %q", tt.name)
			require.Contains(t, err.Error(), tt.errorStrContains, "test: %q", tt.name)
		})
	}
}

// TestConnlistOutputFatalErrors tests fatal errors returned while writing the connlist to string in given output format
func TestConnlistOutputFatalErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name             string
		dirName          string
		format           string
		errorStrContains string
	}{
		{
			name:             "giving_unsupported_output_format_option_should_return_fatal_error",
			dirName:          "onlineboutique",
			format:           "docx",
			errorStrContains: "docx output format is not supported.",
		},
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			analyzerOpts := []ConnlistAnalyzerOption{WithOutputFormat(tt.format)}
			analyzer, res, err := getConnlistFromDirPathRes(analyzerOpts, tt.dirName)
			require.Nil(t, err, "test: %q", tt.name)
			output, err := analyzer.ConnectionsListToString(res)
			require.Empty(t, output, "test: %q", tt.name)
			require.Contains(t, err.Error(), tt.errorStrContains, "test: %q", tt.name)
		})
	}
}

// TestConnlistAnalyzeSevereErrors tests connlist analyzer behavior with severe error, analyzer without stopOnError
// will continue running regularly, analyzer with stopOnError will stop on first severe error and return empty result
func TestConnlistAnalyzeSevereErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name                           string
		dirName                        string
		expectedErrNumWithoutStopOnErr int
		expectedErrNumWithStopOnErr    int
		firstErrStrContains            string
	}{
		{
			name:                           "input_file_has_malformed_yaml_doc_should_return_severe_error",
			dirName:                        filepath.Join("bad_yamls", "document_with_syntax_error.yaml"),
			expectedErrNumWithoutStopOnErr: 2,
			expectedErrNumWithStopOnErr:    1,
			firstErrStrContains:            "YAML document is malformed",
		},
		{
			name:                           "input_file_is_not_a_valid_k8s_resource_should_return_severe_error",
			dirName:                        filepath.Join("bad_yamls", "not_a_k8s_resource.yaml"),
			expectedErrNumWithoutStopOnErr: 2,
			expectedErrNumWithStopOnErr:    2, // an error and a warning
			firstErrStrContains:            "Yaml document is not a K8s resource",
		},
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			analyzerOpts1 := []ConnlistAnalyzerOption{}
			analyzerOpts2 := []ConnlistAnalyzerOption{WithStopOnError()}
			// severe is not fatal, thus not returned
			// first analyzer:
			analyzer, _, err1 := getConnlistFromDirPathRes(analyzerOpts1, tt.dirName)
			resErrors1 := analyzer.Errors()
			require.Nil(t, err1, "test: %q", tt.name)
			require.Equal(t, tt.expectedErrNumWithoutStopOnErr, len(resErrors1), "test: %q", tt.name)
			require.Contains(t, resErrors1[0].Error().Error(), tt.firstErrStrContains, "test: %q", tt.name)
			// second analyzer (with stopOnError):
			analyzerWithStopOnError, res, err2 := getConnlistFromDirPathRes(analyzerOpts2, tt.dirName)
			resErrors2 := analyzerWithStopOnError.Errors()
			require.Nil(t, err2, "test: %q", tt.name)
			require.Empty(t, res, "test: %q", tt.name) // the run stopped on first severe error, no result computed
			require.Equal(t, tt.expectedErrNumWithStopOnErr, len(resErrors2), "test: %q", tt.name)
			require.Contains(t, resErrors2[0].Error().Error(), tt.firstErrStrContains, "test: %q", tt.name)
		})
	}
}

func TestConnlistAnalyzeWarnings(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name                    string
		dirName                 string
		focusWorkload           string
		firstWarningMsgContains string
	}{
		{
			name:                    "input_dir_with_no_yamls_should_get_warnings_no_yamls_and_no_k8s_resources",
			dirName:                 filepath.Join("bad_yamls", "subdir2"),
			firstWarningMsgContains: "no yaml files found",
		},
		{
			name:                    "input_dir_with_focusworkload_that_does_not_exist_should_get_warning",
			dirName:                 "onlineboutique_workloads",
			focusWorkload:           "abcd",
			firstWarningMsgContains: "Workload abcd does not exist in the input resources. Connectivity map report will be empty.",
		},
		{
			name:                    "input_dir_with_focusworkload_ns_and_name_that_does_not_exist_should_get_warning",
			dirName:                 "onlineboutique_workloads",
			focusWorkload:           "default/abcd",
			firstWarningMsgContains: "Workload default/abcd does not exist in the input resources. Connectivity map report will be empty.",
		},
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			analyzerOpts := appendFocusWorkloadOptIfRequired(tt.focusWorkload)
			analyzer, res, err := getConnlistFromDirPathRes(analyzerOpts, tt.dirName)
			require.Empty(t, res, "test: %q", tt.name)
			require.Nil(t, err, "test: %q", tt.name)
			analyzerErrs := analyzer.Errors()
			require.GreaterOrEqual(t, len(analyzerErrs), 1, "test: %q", tt.name) // at least 1 warning
			require.Contains(t, analyzerErrs[0].Error().Error(), tt.firstWarningMsgContains, "test: %q", tt.name)
		})
	}
}

// TestNotContainedOutputLines tests output for non-expected lines to be contained
func TestNotContainedOutputLines(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name                 string
		dirName              string
		focusWorkload        string
		expectedResultLen    int
		extractedLineExample string
	}{
		{
			//	we don't expect to see connections from a workload to itself,
			// even though the focus workload has different replicas which may connect to each other.
			name:                 "connlist_does_not_contain_connections_from_focus_workload_to_itself",
			dirName:              "ipblockstest",
			focusWorkload:        "calico-node",
			expectedResultLen:    49,
			extractedLineExample: "kube-system/calico-node[DaemonSet] => kube-system/calico-node[DaemonSet] : All Connections",
		},
		{
			name:                 "connlist_of_dir_does_not_contain_any_line_of_connections_from_workload_to_itself",
			dirName:              "ipblockstest",
			expectedResultLen:    602,
			extractedLineExample: "kube-system/calico-node[DaemonSet] => kube-system/calico-node[DaemonSet] : All Connections",
		},
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			analyzerOpts := appendFocusWorkloadOptIfRequired(tt.focusWorkload)
			analyzer, res, err := getConnlistFromDirPathRes(analyzerOpts, tt.dirName)
			require.Len(t, res, tt.expectedResultLen, "test: %q", tt.name)
			require.Nil(t, err, "test: %q", tt.name)
			output, err := analyzer.ConnectionsListToString(res)
			require.Nil(t, err, "test: %q", tt.name)
			require.NotContains(t, output, tt.extractedLineExample, "test: %q", tt.name)
		})
	}
}
