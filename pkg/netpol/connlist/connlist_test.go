package connlist

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/np-guard/netpol-analyzer/pkg/internal/testutils"
	"github.com/np-guard/netpol-analyzer/pkg/internal/utils"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/fsscanner"

	"github.com/stretchr/testify/require"
)

const connlistExpectedOutputFileNamePrefix = "connlist_output."
const underscore = "_"

const ResourceInfosFunc = "ConnlistFromResourceInfos"
const DirPathFunc = "ConnlistFromDirPath"

var allFormats = []string{utils.TextFormat, utils.JSONFormat, utils.CSVFormat, utils.MDFormat, utils.DOTFormat}
var connlistTestedAPIS = []string{ResourceInfosFunc, DirPathFunc}

/*
interfaces to  test:
- ConnlistFromResourceInfos
- ConnlistFromDirPath
- ConnectionsListToString

*/

/*
	ConnlistFromResourceInfos:
	Examples for possible errors (non fatal) returned from this call (ResourceInfoListToK8sObjectsList):
	(1) (Warning) malformed k8s resource manifest: "in file: tests\malformed_pod_example\pod.yaml,
	YAML document is malformed: unrecognized type: int32"
	(2) (Warning) malformed k8s resource manifest: "in file: tests\malformed-pod-example-2\pod_list.json,
	 YAML document is malformed: cannot restore slice from map"
	(3) (Warning) no network policy resources found: (tests/malformed_pod_example):
	"no relevant Kubernetes network policy resources found"
	(4) (Error) no workload resources found: (tests/malformed_pod_example/) :
	"no relevant Kubernetes workload resources found"

	Examples for Log Infos that can be printed from this call:
	(1) (Info) in file: tests/bad_yamls/irrelevant_k8s_resources.yaml, skipping object with type: IngressClass

	TODO: add tests to check the Info message is added to the log

	Example for possible fatal-Errors returned from the call below: (connslistFromParsedResources)
	(1) (fatal-err) netpol-err: CIDR error (not a valid ipv4 CIDR)
	(2) additional netpol-err... (e.g. LabelSelector error), and more..
*/

/*
	ConnlistFromDirPath:
	Examples for possible errors returned from this call (GetResourceInfos):
	(1) dir does not exist: "Error: the path "tests/bad_yamls/subdir5" does not exist"
	(2) empty dir : "Error: error reading [tests/bad_yamls/subdir2/]: recognized file
	extensions are [.json .yaml .yml]"
	(3) irrelevant JSON : "GetResourceInfos error: unable to decode "tests\\onlineboutique\\connlist_output.json":
	json: cannot unmarshal array into Go value of type unstructured.detector"
	(4) bad JSON/YAML - missing kind : "Error: unable to decode "tests\\malformed-pod-example-4\\pods.json":
	 Object 'Kind' is missing in '{ ... }"
	(5) YAML doc with syntax error: "error parsing tests/bad_yamls/document_with_syntax_error.yaml: error
	converting YAML to JSON: yaml: line 19: found character that cannot start any token"

*/

/////////////////////////////////////good path tests /////////////////////////////////////////////////////////////////////////////////

// TestConnList tests the output of ConnlistFromDirPath() for valid input resources
func TestConnListFromDir(t *testing.T) {
	t.Parallel()
	for _, tt := range goodPathTests {
		tt := tt
		t.Run(tt.testDirName, func(t *testing.T) {
			t.Parallel()
			for _, format := range tt.outputFormats {
				pTest := prepareTest(tt.testDirName, tt.focusWorkload, format)
				res, _, err := pTest.analyzer.ConnlistFromDirPath(pTest.dirPath)
				require.Nil(t, err, pTest.testInfo)
				output, err := pTest.analyzer.ConnectionsListToString(res)
				require.Nil(t, err, pTest.testInfo)
				testutils.CheckActualVsExpectedOutputMatch(t, pTest.testName, tt.testDirName,
					pTest.expectedOutputFileName, output, pTest.testInfo)
			}
		})
	}
}

func TestConnListFromResourceInfos(t *testing.T) {
	t.Parallel()
	for _, tt := range goodPathTests {
		tt := tt
		t.Run(tt.testDirName, func(t *testing.T) {
			t.Parallel()
			for _, format := range tt.outputFormats {
				pTest := prepareTest(tt.testDirName, tt.focusWorkload, format)
				infos, _ := fsscanner.GetResourceInfosFromDirPath([]string{pTest.dirPath}, true, false)
				// require.Empty(t, errs, testInfo) - TODO: add info about expected errors
				// from each test here (these errors do not stop the analysis or affect the output)
				// more suitable to test this in a separate package (manifests) where  GetResourceInfosFromDirPath is implemented
				res, _, err := pTest.analyzer.ConnlistFromResourceInfos(infos)
				require.Nil(t, err, pTest.testInfo)
				output, err := pTest.analyzer.ConnectionsListToString(res)
				require.Nil(t, err, pTest.testInfo)
				testutils.CheckActualVsExpectedOutputMatch(t, pTest.testName, tt.testDirName,
					pTest.expectedOutputFileName, output, pTest.testInfo)
			}
		})
	}
}

/////////////////////////////////////bad path tests /////////////////////////////////////////////////////////////////////////////////

// fatal errors common for both interfaces (ConnlistFromDirPath & ConnlistFromResourceInfos)
//--------------------------------------------------------------------------------------------

func TestConnlistAnalyzeFatalErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name             string
		dirName          string
		errorStrContains string
	}{
		// invalid netpols batch
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
		/*// input dir does not exist
		{
			name:             "Input_dir_does_not_exist_should_return_fatal_error_accessing_directory",
			dirName:          filepath.Join("bad_yamls", "subdir3"),
			errorStrContains: "does not exist", // TODO: actual msg: "the path ... does not exist"
		},*/
		// pods list issue - pods with same owner but different labels
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
			for _, apiToTest := range connlistTestedAPIS {
				analyzer, connsRes, peersRes, err := getAnalysisResFromAPI(apiToTest, tt.dirName, "")
				testFatalErr(t, connsRes, peersRes, err, tt.name, tt.errorStrContains, analyzer)
			}
		})
	}
}

func testFatalErr(t *testing.T,
	connsRes []Peer2PeerConnection,
	peersRes []Peer,
	err error,
	testName, errStr string,
	analyzer *ConnlistAnalyzer) {
	require.Empty(t, connsRes, testName)
	require.Empty(t, peersRes, testName)
	testutils.CheckErrorContainment(t, testName, errStr, err.Error())
	require.Equal(t, len(analyzer.errors), 1)
	testutils.CheckErrorContainment(t, testName, errStr, analyzer.errors[0].Error().Error())
}

func getAnalysisResFromAPI(apiName, dirName, focusWorkload string) (
	analyzer *ConnlistAnalyzer, connsRes []Peer2PeerConnection, peersRes []Peer, err error) {
	pTest := prepareTest(dirName, focusWorkload, utils.DefaultFormat)
	switch apiName {
	case ResourceInfosFunc:
		infos, _ := fsscanner.GetResourceInfosFromDirPath([]string{pTest.dirPath}, true, false)
		connsRes, peersRes, err = pTest.analyzer.ConnlistFromResourceInfos(infos)
	case DirPathFunc:
		connsRes, peersRes, err = pTest.analyzer.ConnlistFromDirPath(pTest.dirPath)
	}
	return pTest.analyzer, connsRes, peersRes, err
}

// severe errors and warnings, common for both interfaces (ConnlistFromDirPath & ConnlistFromResourceInfos)
//--------------------------------------------------------------------------------------------

// TODO: test stopOnErr here?

//nolint:gocritic //temporary commented-out code
func TestConnlistAnalyzeSevereErrorsAndWarnings(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name                string
		dirName             string
		firstErrStrContains string
		emptyRes            bool
		focusWorkload       string
		/*expectedErrNumWithoutStopOnErr int
		expectedErrNumWithStopOnErr    int*/
	}{

		{
			name:                "input_file_has_no_relevant_k8s_resources",
			dirName:             filepath.Join("bad_yamls", "irrelevant_k8s_resources.yaml"),
			firstErrStrContains: "no relevant Kubernetes workload resources found",
			emptyRes:            true,
		},
		{
			name:                "no_network_policy_resources_warning",
			dirName:             "no_netpols_dir",
			firstErrStrContains: "no relevant Kubernetes network policy resources found",
			emptyRes:            false,
		},
		/*
			$ ./bin/k8snetpolicy list --dirpath tests/malformed_pod_example/
			2023/11/02 08:56:16 : err : in file: tests\malformed_pod_example\pod.yaml YAML document is malformed:
			 error for resource with kind: Pod , name: nginx , :  unrecognized type: int32
			2023/11/02 08:56:16 : no relevant Kubernetes workload resources found
			2023/11/02 08:56:16 no relevant Kubernetes network policy resources found


		*/
		{
			name:                "malformed_yaml_unrecognized_type_int32",
			dirName:             "malformed_pod_example",
			firstErrStrContains: "unrecognized type: int32",
			emptyRes:            true,
		},
		{
			name:                "malformed_yaml_cannot_restore_slice_from_map",
			dirName:             "malformed-pod-example-2",
			firstErrStrContains: "cannot restore slice from map",
			emptyRes:            false,
		},
		{
			name:                "input_dir_with_focusworkload_that_does_not_exist_should_get_warning",
			dirName:             "onlineboutique_workloads",
			focusWorkload:       "abcd",
			firstErrStrContains: "Workload abcd does not exist in the input resources. Connectivity map report will be empty.",
			emptyRes:            true,
		},
		{
			name:                "input_dir_with_focusworkload_ns_and_name_that_does_not_exist_should_get_warning",
			dirName:             "onlineboutique_workloads",
			focusWorkload:       "default/abcd",
			firstErrStrContains: "Workload default/abcd does not exist in the input resources. Connectivity map report will be empty.",
			emptyRes:            true,
		},

		/*{
			// this error issued by builder
			name:                           "input_file_has_malformed_yaml_doc_should_return_severe_error",
			dirName:                        filepath.Join("bad_yamls", "document_with_syntax_error.yaml"),
			expectedErrNumWithoutStopOnErr: 2,
			expectedErrNumWithStopOnErr:    1,
			firstErrStrContains:            "found character that cannot start any token", //"YAML document is malformed",
		},
		{
			// this error issued by builder
			name:                           "input_file_is_not_a_valid_k8s_resource_should_return_severe_error",
			dirName:                        filepath.Join("bad_yamls", "not_a_k8s_resource.yaml"),
			expectedErrNumWithoutStopOnErr: 3,                  //2,
			expectedErrNumWithStopOnErr:    2,                  // an error and a warning
			firstErrStrContains:            "unable to decode", //"Yaml document is not a K8s resource",
		},*/
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			for _, apiToTest := range connlistTestedAPIS {
				analyzer, connsRes, peersRes, err := getAnalysisResFromAPI(apiToTest, tt.dirName, tt.focusWorkload)
				require.Nil(t, err, tt.name)
				if tt.emptyRes {
					require.Empty(t, connsRes, tt.name)
					require.Empty(t, peersRes, tt.name)
				} else {
					require.NotEmpty(t, connsRes, tt.name)
					require.NotEmpty(t, peersRes, tt.name)
				}
				testutils.CheckErrorContainment(t, tt.name, tt.firstErrStrContains, analyzer.errors[0].Error().Error())
			}

			/*analyzerOpts1 := []ConnlistAnalyzerOption{}
			analyzerOpts2 := []ConnlistAnalyzerOption{WithStopOnError()}
			// severe is not fatal, thus not returned
			// first analyzer:
			analyzer, _, err1 := getConnlistFromDirPathRes(analyzerOpts1, tt.dirName)
			resErrors1 := analyzer.Errors()
			require.Nil(t, err1, "test: %q", tt.name)
			require.Equal(t, tt.expectedErrNumWithoutStopOnErr, len(resErrors1), "test: %q", tt.name)
			testutils.CheckErrorContainment(t, tt.name, tt.firstErrStrContains, resErrors1[0].Error().Error(), true)
			// second analyzer (with stopOnError):

			analyzerWithStopOnError, res, err2 := getConnlistFromDirPathRes(analyzerOpts2, tt.dirName)
			resErrors2 := analyzerWithStopOnError.Errors()
			require.Nil(t, err2, "test: %q", tt.name)
			require.Empty(t, res, "test: %q", tt.name) // the run stopped on first severe error, no result computed
			require.Equal(t, tt.expectedErrNumWithStopOnErr, len(resErrors2), "test: %q", tt.name)
			testutils.CheckErrorContainment(t, tt.name, tt.firstErrStrContains, resErrors2[0].Error().Error(), true)*/
		})
	}
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Test errs/warnings unique for ConnlistFromDirPath only (issued by the resources builder)
// ----------------------------------------------------------------------------------------------

func TestFatalErrorsConnlistFromDirPathOnly(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name             string
		dirName          string
		errorStrContains string
	}{
		{
			name:             "dir_does_not_exist_err",
			dirName:          "ttt",
			errorStrContains: "does not exist",
		},
		{
			name:             "empty_dir_with_no_yamls_or_json_files",
			dirName:          filepath.Join("bad_yamls", "subdir2"),
			errorStrContains: "recognized file extensions are",
		},
		{
			name:             "bad_JSON_missing_kind", // this err is fatal here only because dir has no other resources
			dirName:          "malformed-pod-example-4",
			errorStrContains: "is missing in", // kind is missing in pod json
		},
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			analyzer, connsRes, peersRes, err := getAnalysisResFromAPI(DirPathFunc, tt.dirName, "")
			testFatalErr(t, connsRes, peersRes, err, tt.name, tt.errorStrContains, analyzer)
		})
	}
}

func TestErrorsAndWarningsConnlistFromDirPathOnly(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name             string
		dirName          string
		errorStrContains string
		emptyRes         bool
		focusWorkload    string
	}{
		{
			name:             "irrelevant_JSON_file_unable_to_decode",
			dirName:          "onlineboutique",
			errorStrContains: "cannot unmarshal array into Go value of type unstructured.detector",
			emptyRes:         false,
		},
		{
			name:             "YAML_syntax_err",
			dirName:          "malformed-pod-example-5",
			errorStrContains: "found character that cannot start any token",
			emptyRes:         false,
			// TODO: this test has another error (missing kind in another file), add this to the testing functionality
		},
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			analyzer, connsRes, peersRes, err := getAnalysisResFromAPI(DirPathFunc, tt.dirName, tt.focusWorkload)
			require.Nil(t, err, tt.name)
			if tt.emptyRes {
				require.Empty(t, connsRes, tt.name)
				require.Empty(t, peersRes, tt.name)
			} else {
				require.NotEmpty(t, connsRes, tt.name)
				require.NotEmpty(t, peersRes, tt.name)
			}
			testutils.CheckErrorContainment(t, tt.name, tt.errorStrContains, analyzer.errors[0].Error().Error())
		})
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////

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
			require.NotContains(t, output, tt.extractedLineExample, "test: %q, output should not contain %q", tt.name, tt.extractedLineExample)
		})
	}
}

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
/*func verifyConnlistAnalyzeOutputVsExpectedOutput(t *testing.T, analyzerOptions []ConnlistAnalyzerOption, dirName,
	expectedOutputFileName, testName, format string) {
	analyzer, res, err := getConnlistFromDirPathRes(analyzerOptions, dirName)
	require.Nil(t, err, testutils.GetDebugMsgWithTestNameAndFormat(testName, format))
	output, err := analyzer.ConnectionsListToString(res)
	require.Nil(t, err, testutils.GetDebugMsgWithTestNameAndFormat(testName, format))
	testutils.CheckActualVsExpectedOutputMatch(t, testName, dirName, expectedOutputFileName, output, format)
}*/

// helping func - if focus workload is not empty append it to ConnlistAnalyzerOption list
func appendFocusWorkloadOptIfRequired(focusWorkload string) []ConnlistAnalyzerOption {
	analyzerOptions := []ConnlistAnalyzerOption{}
	if focusWorkload != "" {
		analyzerOptions = append(analyzerOptions, WithFocusWorkload(focusWorkload))
	}
	return analyzerOptions
}

func testNameByTestType(dirName, focusWorkload, format string) (testName, expectedOutputFileName string) {
	switch {
	case focusWorkload == "":
		return dirName, connlistExpectedOutputFileNamePrefix + format

	case focusWorkload != "":
		focusWorkloadStr := strings.Replace(focusWorkload, "/", underscore, 1)
		return "dir_" + dirName + "_focus_workload_" + focusWorkloadStr,
			focusWorkloadStr + underscore + connlistExpectedOutputFileNamePrefix + format
	}
	return "", ""
}

type preparedTest struct {
	testName               string
	testInfo               string
	dirPath                string
	expectedOutputFileName string
	analyzer               *ConnlistAnalyzer
}

func prepareTest(dirName, focusWorkload, format string) preparedTest {
	res := preparedTest{}
	res.testName, res.expectedOutputFileName = testNameByTestType(dirName, focusWorkload, format)
	res.testInfo = testutils.GetDebugMsgWithTestNameAndFormat(res.testName, format)
	res.analyzer = NewConnlistAnalyzer(WithOutputFormat(format), WithFocusWorkload(focusWorkload))
	res.dirPath = getDirPathFromDirName(dirName)
	return res
}

// fatal errors for interface ConnectionsListToString
//--------------------------------------------------------------------------------------------

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
			preparedTest := prepareTest(tt.dirName, "", tt.format)
			connsRes, peersRes, err := preparedTest.analyzer.ConnlistFromDirPath(preparedTest.dirPath)

			require.Nil(t, err, tt.name)
			// "unable to decode ... connlist_output.json"
			require.Equal(t, len(preparedTest.analyzer.errors), 1, "expecting error since builder not able to parse connlist_output.json")
			require.NotEmpty(t, connsRes, "expecting non-empty analysis res")
			require.NotEmpty(t, peersRes, "expecting non-empty analysis res")

			output, err := preparedTest.analyzer.ConnectionsListToString(connsRes)
			require.Empty(t, output, tt.name)
			testutils.CheckErrorContainment(t, tt.name, tt.errorStrContains, err.Error())

			// re-run the test with new analyzer (to clear the analyzer.errors array )
			preparedTest = prepareTest(tt.dirName, "", tt.format)
			infos, _ := fsscanner.GetResourceInfosFromDirPath([]string{preparedTest.dirPath}, true, false)
			connsRes2, peersRes2, err2 := preparedTest.analyzer.ConnlistFromResourceInfos(infos)

			require.Nil(t, err2, tt.name)
			require.Empty(t, preparedTest.analyzer.errors, "expecting no errors from ConnlistFromResourceInfos")
			require.NotEmpty(t, connsRes2, "expecting non-empty analysis res")
			require.NotEmpty(t, peersRes2, "expecting non-empty analysis res")

			output, err2 = preparedTest.analyzer.ConnectionsListToString(connsRes)
			require.Empty(t, output, tt.name)
			testutils.CheckErrorContainment(t, tt.name, tt.errorStrContains, err2.Error())
		})
	}
}

var goodPathTests = []struct {
	testDirName   string
	outputFormats []string
	focusWorkload string
}{
	{
		testDirName:   "ipblockstest",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "onlineboutique",
		outputFormats: []string{utils.JSONFormat, utils.MDFormat, utils.TextFormat},
	},
	{
		testDirName:   "onlineboutique_workloads",
		outputFormats: []string{utils.CSVFormat, utils.DOTFormat, utils.TextFormat},
	},
	{
		testDirName:   "minikube_resources",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "online_boutique_workloads_no_ns",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "core_pods_without_host_ip",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "acs_security_frontend_demos",
		outputFormats: allFormats,
	},
	{
		testDirName:   "demo_app_with_routes_and_ingress",
		outputFormats: allFormats,
	},
	{
		testDirName:   "k8s_ingress_test",
		outputFormats: allFormats,
	},
	{
		testDirName:   "multiple_ingress_objects_with_different_ports",
		outputFormats: allFormats,
	},
	{
		testDirName:   "one_ingress_multiple_ports",
		outputFormats: allFormats,
	},
	{
		testDirName:   "one_ingress_multiple_services",
		outputFormats: allFormats,
	},
	{
		testDirName:   "acs-security-demos",
		outputFormats: allFormats,
	},
	{
		testDirName:   "acs-security-demos-with-netpol-list",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "test_with_named_ports",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "test_with_named_ports_changed_netpol",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "netpol-analysis-example-minimal",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "with_end_port_example",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "with_end_port_example_new",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "new_online_boutique",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "new_online_boutique_synthesis",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "multiple_topology_resources_1",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "multiple_topology_resources_2",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "multiple_topology_resources_3",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "multiple_topology_resources_4",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "minimal_test_in_ns",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "semanticDiff-same-topologies-old1",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "semanticDiff-same-topologies-old2",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "semanticDiff-same-topologies-old3",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "semanticDiff-same-topologies-new1",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "semanticDiff-same-topologies-new1a",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "semanticDiff-same-topologies-new2",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "semanticDiff-same-topologies-new3",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "semanticDiff-orig-topologies-no-policy",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "semanticDiff-orig-topologies-policy-a",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "semanticDiff-different-topologies-policy-a",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "semanticDiff-different-topologies-policy-b",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "ipblockstest_2",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "ipblockstest_3",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "ipblockstest_4",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "semanticDiff-different-topologies-policy-a-with-ipblock",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "semanticDiff-different-topologies-policy-b-with-ipblock",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "test_with_named_ports_changed_netpol_2",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "onlineboutique_workloads",
		focusWorkload: "emailservice",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "k8s_ingress_test",
		focusWorkload: "details-v1-79f774bdb9",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "acs-security-demos-added-workloads",
		focusWorkload: "backend/recommendation",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "acs-security-demos-added-workloads",
		focusWorkload: "asset-cache",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "acs-security-demos-added-workloads",
		focusWorkload: "frontend/asset-cache",
		outputFormats: []string{utils.TextFormat},
	},
	{
		testDirName:   "acs-security-demos-added-workloads",
		focusWorkload: "ingress-controller",
		outputFormats: []string{utils.TextFormat},
	},
}
