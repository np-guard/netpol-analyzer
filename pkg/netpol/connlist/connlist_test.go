/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connlist

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
	"github.com/np-guard/netpol-analyzer/pkg/internal/output"
	"github.com/np-guard/netpol-analyzer/pkg/internal/testutils"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/fsscanner"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/alerts"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/examples"

	"github.com/stretchr/testify/require"
)

const ResourceInfosFunc = "ConnlistFromResourceInfos"
const DirPathFunc = "ConnlistFromDirPath"
const currentPkg = "connlist"
const notEmptyMsg = "expecting non-empty analysis res"

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

	Example for possible fatal-Errors returned from the call below: (connsListFromParsedResources)
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
	(5) YAML doc with syntax error: "error parsing tests/document_with_syntax_error.yaml: error
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
				pTest := prepareTest(tt.testDirName, tt.focusWorkload, format, tt.exposureAnalysis)
				res, _, err := pTest.analyzer.ConnlistFromDirPath(pTest.dirPath)
				require.Nil(t, err, pTest.testInfo)
				out, err := pTest.analyzer.ConnectionsListToString(res)
				require.Nil(t, err, pTest.testInfo)
				testutils.CheckActualVsExpectedOutputMatch(t, pTest.expectedOutputFileName, out,
					pTest.testInfo, currentPkg)
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
				pTest := prepareTest(tt.testDirName, tt.focusWorkload, format, tt.exposureAnalysis)
				infos, _ := fsscanner.GetResourceInfosFromDirPath([]string{pTest.dirPath}, true, false)
				// require.Empty(t, errs, testInfo) - TODO: add info about expected errors
				// from each test here (these errors do not stop the analysis or affect the output)
				// more suitable to test this in a separate package (manifests) where  GetResourceInfosFromDirPath is implemented
				res, _, err := pTest.analyzer.ConnlistFromResourceInfos(infos)
				require.Nil(t, err, pTest.testInfo)
				out, err := pTest.analyzer.ConnectionsListToString(res)
				require.Nil(t, err, pTest.testInfo)
				testutils.CheckActualVsExpectedOutputMatch(t, pTest.expectedOutputFileName, out,
					pTest.testInfo, currentPkg)
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
			errorStrContains: netpolerrors.ConcatErrors(netpolerrors.CidrErrTitle, netpolerrors.InvalidCIDRAddr),
		},
		{
			name:             "Input_dir_has_netpol_with_bad_label_key_should_return_fatal_selector_error",
			dirName:          filepath.Join("bad_netpols", "subdir2"),
			errorStrContains: netpolerrors.ConcatErrors(netpolerrors.SelectorErrTitle, netpolerrors.InvalidKeyVal),
		},
		{
			name:             "Input_dir_has_netpol_with_invalid_rule_peer_should_return_fatal_rule_NetworkPolicyPeer_error",
			dirName:          filepath.Join("bad_netpols", "subdir3"),
			errorStrContains: netpolerrors.ConcatErrors(netpolerrors.RulePeerErrTitle, netpolerrors.CombinedRulePeerErrStr),
		},
		{
			name:             "Input_dir_has_netpol_with_empty_rule_peer_should_return_fatal_rule_NetworkPolicyPeer_error",
			dirName:          filepath.Join("bad_netpols", "subdir4"),
			errorStrContains: netpolerrors.ConcatErrors(netpolerrors.RulePeerErrTitle, netpolerrors.EmptyRulePeerErrStr),
		},
		{
			name:             "Input_dir_has_netpol_with_named_port_on_ipblock_peer_should_return_fatal_named_port_error",
			dirName:          filepath.Join("bad_netpols", "subdir6"),
			errorStrContains: netpolerrors.ConcatErrors(netpolerrors.NamedPortErrTitle, netpolerrors.ConvertNamedPortErrStr),
		},
		/*// input dir does not exist
		{
			name:             "Input_dir_does_not_exist_should_return_fatal_error_accessing_directory",
			dirName:          filepath.Join("bad_yamls", "subdir3"),
			errorStrContains: "does not exist", // TODO: actual msg: "the path ... does not exist"
		},*/
		// pods list issue - pods with same owner but different labels
		{
			name:             "Input_dir_has_illegal_podlist_pods_with_same_owner_ref_name_has_different_labels_should_return_fatal_error",
			dirName:          "semanticDiff-same-topologies-illegal-podlist",
			errorStrContains: netpolerrors.NotSupportedPodResourcesErrorStr("demo/cog-agents"),
		},
		{
			name:             "Input_dir_has_two_netpols_with_same_name_in_a_namespace_should_return_fatal_error_of_existing_object",
			dirName:          "np_bad_path_test_1",
			errorStrContains: netpolerrors.NPWithSameNameError("default/backend-netpol"),
		},
		// anp & banp bad path tests
		{
			name:             "Input_dir_has_two_admin_netpols_with_same_priority_should_return_fatal_error",
			dirName:          "anp_bad_path_test_1",
			errorStrContains: netpolerrors.PriorityErrExplain,
		},
		{
			name:             "Input_dir_has_an_admin_netpol_with_invalid_priority_should_return_fatal_error",
			dirName:          "anp_bad_path_test_2",
			errorStrContains: netpolerrors.PriorityValueErr("invalid-priority", 1001),
		},
		{
			name:             "Input_dir_has_two_admin_netpols_with_same_name_should_return_fatal_error",
			dirName:          "anp_bad_path_test_3",
			errorStrContains: netpolerrors.ANPsWithSameNameErr("same-name"),
		},
		{
			name:             "Input_dir_has_an_admin_netpol_with_empty_subject_should_return_fatal_error",
			dirName:          "anp_bad_path_test_4",
			errorStrContains: netpolerrors.OneFieldSetSubjectErr,
		},
		{
			name:             "Input_dir_has_an_admin_netpol_with_invalid_subject_should_return_fatal_error",
			dirName:          "anp_bad_path_test_5",
			errorStrContains: netpolerrors.OneFieldSetSubjectErr,
		},
		{
			name:             "Input_dir_has_an_admin_netpol_with_an_empty_egress_rule_peer_should_return_fatal_error",
			dirName:          "anp_bad_path_test_6",
			errorStrContains: netpolerrors.ANPEgressRulePeersErr,
		},
		{
			name:             "Input_dir_has_an_admin_netpol_with_an_invalid_egress_rule_peer_should_return_fatal_error",
			dirName:          "anp_bad_path_test_7",
			errorStrContains: netpolerrors.OneFieldSetRulePeerErr,
		},
		{
			name:             "Input_dir_has_an_admin_netpol_with_an_invalid_egress_rule_port_should_return_fatal_error",
			dirName:          "anp_bad_path_test_8",
			errorStrContains: netpolerrors.ANPPortsError,
		},
		{
			name:             "Input_dir_has_an_admin_netpol_with_an_invalid_egress_rule_action_should_return_fatal_error",
			dirName:          "anp_bad_path_test_9",
			errorStrContains: netpolerrors.UnknownRuleActionErr,
		},
		{
			name:             "Input_dir_has_an_admin_netpol_missing_egress_rule_peer_should_return_fatal_error",
			dirName:          "anp_bad_path_test_10",
			errorStrContains: netpolerrors.ANPEgressRulePeersErr,
		},
		{
			name:             "Input_dir_has_an_admin_netpol_missing_egress_rule_action_should_return_fatal_error",
			dirName:          "anp_bad_path_test_12",
			errorStrContains: netpolerrors.UnknownRuleActionErr,
		},
		{
			name:             "Input_dir_has_an_admin_netpol_missing_ingress_rule_peer_should_return_fatal_error",
			dirName:          "anp_bad_path_test_14",
			errorStrContains: netpolerrors.ANPIngressRulePeersErr,
		},
		{
			name:             "Input_dir_has_an_admin_netpol_with_an_empty_ingress_rule_peer_should_return_fatal_error",
			dirName:          "anp_bad_path_test_15",
			errorStrContains: netpolerrors.ANPIngressRulePeersErr,
		},
		{
			name:             "Input_dir_has_an_admin_netpol_with_an_invalid_ingress_rule_peer_should_return_fatal_error",
			dirName:          "anp_bad_path_test_16",
			errorStrContains: netpolerrors.OneFieldSetRulePeerErr,
		},
		{
			name:             "Input_dir_has_an_admin_netpol_with_an_invalid_ingress_rule_port_should_return_fatal_error",
			dirName:          "anp_bad_path_test_17",
			errorStrContains: netpolerrors.ANPPortsError,
		},
		{
			name:             "Input_dir_has_an_admin_netpol_with_an_invalid_ingress_rule_action_should_return_fatal_error",
			dirName:          "anp_bad_path_test_18",
			errorStrContains: netpolerrors.UnknownRuleActionErr,
		},
		{
			name:             "Input_dir_has_more_than_one_baseline_admin_netpol_should_return_fatal_error",
			dirName:          "banp_bad_path_test_1",
			errorStrContains: netpolerrors.BANPAlreadyExists,
		},
		{
			name:             "Input_dir_has_baseline_admin_netpol_with_name_not_default_should_return_fatal_error",
			dirName:          "banp_bad_path_test_2",
			errorStrContains: netpolerrors.BANPNameAssertion,
		},
		{
			name:             "Input_dir_has_baseline_admin_netpol_with_empty_subject_should_return_fatal_error",
			dirName:          "banp_bad_path_test_3",
			errorStrContains: netpolerrors.OneFieldSetSubjectErr,
		},
		{
			name:             "Input_dir_has_baseline_admin_netpol_with_invalid_subject_should_return_fatal_error",
			dirName:          "banp_bad_path_test_4",
			errorStrContains: netpolerrors.OneFieldSetSubjectErr,
		},
		{
			name:             "Input_dir_has_baseline_admin_netpol_with_an_empty_egress_rule_peer_should_return_fatal_error",
			dirName:          "banp_bad_path_test_5",
			errorStrContains: netpolerrors.ANPEgressRulePeersErr,
		},
		{
			name:             "Input_dir_has_baseline_admin_netpol_with_missing_egress_rule_peer_should_return_fatal_error",
			dirName:          "banp_bad_path_test_6",
			errorStrContains: netpolerrors.ANPEgressRulePeersErr,
		},
		{
			name:             "Input_dir_has_baseline_admin_netpol_with_an_invalid_egress_rule_peer_should_return_fatal_error",
			dirName:          "banp_bad_path_test_7",
			errorStrContains: netpolerrors.OneFieldSetRulePeerErr,
		},
		{
			name:             "Input_dir_has_baseline_admin_netpol_with_an_invalid_egress_rule_action_should_return_fatal_error",
			dirName:          "banp_bad_path_test_8",
			errorStrContains: netpolerrors.UnknownRuleActionErr,
		},
		{
			name:             "Input_dir_has_baseline_admin_netpol_with_an_invalid_egress_rule_port_should_return_fatal_error",
			dirName:          "banp_bad_path_test_9",
			errorStrContains: netpolerrors.ANPPortsError,
		},
		{
			name:             "Input_dir_has_baseline_admin_netpol_with_missing_ingress_rule_peer_should_return_fatal_error",
			dirName:          "banp_bad_path_test_10",
			errorStrContains: netpolerrors.ANPIngressRulePeersErr,
		},
		{
			name:             "Input_dir_has_baseline_admin_netpol_with_an_empty_ingress_rule_peer_should_return_fatal_error",
			dirName:          "banp_bad_path_test_11",
			errorStrContains: netpolerrors.ANPIngressRulePeersErr,
		},
		{
			name:             "Input_dir_has_baseline_admin_netpol_with_an_invalid_ingress_rule_peer_should_return_fatal_error",
			dirName:          "banp_bad_path_test_12",
			errorStrContains: netpolerrors.OneFieldSetRulePeerErr,
		},
		{
			name:             "Input_dir_has_baseline_admin_netpol_with_an_invalid_ingress_rule_port_should_return_fatal_error",
			dirName:          "banp_bad_path_test_13",
			errorStrContains: netpolerrors.ANPPortsError,
		},
		{
			name:             "Input_dir_has_baseline_admin_netpol_with_an_invalid_ingress_rule_action_should_return_fatal_error",
			dirName:          "banp_bad_path_test_14",
			errorStrContains: netpolerrors.UnknownRuleActionErr,
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
	pTest := prepareTest(dirName, focusWorkload, output.DefaultFormat, false)
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
			firstErrStrContains: netpolerrors.NoK8sWorkloadResourcesFoundErrorStr,
			emptyRes:            true,
		},
		{
			name:                "no_network_policy_resources_warning",
			dirName:             "no_netpols_dir",
			firstErrStrContains: netpolerrors.NoK8sNetworkPolicyResourcesFoundErrorStr,
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
			firstErrStrContains: netpolerrors.UnrecognizedValType, // netpolerrors.MalformedYamlDocErrorStr
			emptyRes:            true,
		},
		{
			name:                "malformed_yaml_cannot_restore_slice_from_map",
			dirName:             "malformed-pod-example-2",
			firstErrStrContains: netpolerrors.SliceFromMapErr, // netpolerrors.MalformedYamlDocErrorStr
			emptyRes:            false,
		},
		{
			name:                "input_dir_with_focusworkload_that_does_not_exist_should_get_warning",
			dirName:             "onlineboutique_workloads",
			focusWorkload:       "abcd",
			firstErrStrContains: netpolerrors.WorkloadDoesNotExistErrStr("abcd"),
			emptyRes:            true,
		},
		{
			name:                "input_dir_with_focusworkload_ns_and_name_that_does_not_exist_should_get_warning",
			dirName:             "onlineboutique_workloads",
			focusWorkload:       "default/abcd",
			firstErrStrContains: netpolerrors.WorkloadDoesNotExistErrStr("default/abcd"),
			emptyRes:            true,
		},

		/*{
			// this error issued by builder
			name:                           "input_file_has_malformed_yaml_doc_should_return_severe_error",
			dirName:                        "document_with_syntax_error",
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
			errorStrContains: netpolerrors.PathNotExistErr, // netpolerrors.ErrGettingResInfoFromDir
		},
		{
			name:             "empty_dir_with_no_yamls_or_json_files",
			dirName:          filepath.Join("bad_yamls", "subdir2"),
			errorStrContains: netpolerrors.UnknownFileExtensionErr, // netpolerrors.ErrGettingResInfoFromDir
		},
		{
			name:             "bad_JSON_missing_kind", // this err is fatal here only because dir has no other resources
			dirName:          "malformed-pod-example-4",
			errorStrContains: netpolerrors.MissingObjectErr, // kind is missing in pod json, netpolerrors.ErrGettingResInfoFromDir
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
			errorStrContains: netpolerrors.UnmarshalErr, // netpolerrors.FailedReadingFileErrorStr
			emptyRes:         false,
		},
		{
			name:             "YAML_syntax_err",
			dirName:          "malformed-pod-example-5",
			errorStrContains: netpolerrors.WrongStartCharacterErr, // netpolerrors.FailedReadingFileErrorStr
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

func TestLoggerWarnings(t *testing.T) {
	// this test contains writing to a buffer , so it is not running in parallel to other tests.
	// (we need to add mutex to the TestLogger if we wish to run the tests in parallel)
	cases := []struct {
		name                        string
		dirName                     string
		expectedWarningsStrContains []string
	}{
		{
			name:                        "input_admin_policy_contains_nodes_egress_peer_should_get_warning",
			dirName:                     "anp_and_banp_using_networks_and_nodes_test",
			expectedWarningsStrContains: []string{alerts.WarnUnsupportedNodesField},
		},
		{
			name:                        "input_admin_policy_contains_ipv6_addresses_in_networks_egress_peer_should_get_warning",
			dirName:                     "anp_and_banp_using_networks_with_ipv6_test",
			expectedWarningsStrContains: []string{alerts.WarnUnsupportedIPv6Address},
		},
		{
			name:    "input_admin_policy_contains_unsupported_fields_and_unknown_named_port_should_get_some_warnings",
			dirName: "anp_banp_test_multiple_warnings",
			expectedWarningsStrContains: []string{
				alerts.WarnUnsupportedIPv6Address,
				alerts.WarnUnsupportedNodesField,
				alerts.WarnPrefixPortName,
			},
		},
		{
			name:                        "input_admin_policy_contains_unknown_port_name_should_get_warning",
			dirName:                     "anp_banp_test_with_named_port_unmatched",
			expectedWarningsStrContains: []string{alerts.WarnPrefixPortName},
		},
		{
			name:                        "input_admin_policy_contains_empty_port_range_should_get_warning",
			dirName:                     "anp_test_with_empty_port_range",
			expectedWarningsStrContains: []string{alerts.WarnEmptyPortRange},
		},
		{
			name:                        "input_admin_policy_contains_named_port_with_networks_should_get_warning",
			dirName:                     "anp_test_named_ports_multiple_peers",
			expectedWarningsStrContains: []string{alerts.WarnNamedPortIgnoredForIP},
		},
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			tLogger := testutils.NewTestLogger()
			_, _, err := getConnlistFromDirPathRes([]ConnlistAnalyzerOption{WithLogger(tLogger)}, tt.dirName)
			require.Nil(t, err, "test: %q", tt.name)
			logMsges := tLogger.GetLoggerMessages()
			for _, warn := range tt.expectedWarningsStrContains {
				require.Contains(t, logMsges, warn,
					"test: %q; logger warnings do not contain the expected warning : %q", tt.name, warn)
			}
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
			out, err := analyzer.ConnectionsListToString(res)
			require.Nil(t, err, "test: %q", tt.name)
			require.NotContains(t, out, tt.extractedLineExample, "test: %q, output should not contain %q", tt.name, tt.extractedLineExample)
		})
	}
}

// helping func - creates ConnlistAnalyzer with desired opts and returns the analyzer with connlist from provided directory
func getConnlistFromDirPathRes(opts []ConnlistAnalyzerOption, dirName string) (*ConnlistAnalyzer, []Peer2PeerConnection, error) {
	analyzer := NewConnlistAnalyzer(opts...)
	res, _, err := analyzer.ConnlistFromDirPath(testutils.GetTestDirPath(dirName))
	return analyzer, res, err
}

// helping func - if focus workload is not empty append it to ConnlistAnalyzerOption list
func appendFocusWorkloadOptIfRequired(focusWorkload string) []ConnlistAnalyzerOption {
	analyzerOptions := []ConnlistAnalyzerOption{}
	if focusWorkload != "" {
		analyzerOptions = append(analyzerOptions, WithFocusWorkload(focusWorkload))
	}
	return analyzerOptions
}

type preparedTest struct {
	testName               string
	testInfo               string
	dirPath                string
	expectedOutputFileName string
	analyzer               *ConnlistAnalyzer
}

func prepareTest(dirName, focusWorkload, format string, exposureFlag bool) preparedTest {
	res := preparedTest{}
	res.testName, res.expectedOutputFileName = testutils.ConnlistTestNameByTestArgs(dirName, focusWorkload, format, exposureFlag)
	res.testInfo = fmt.Sprintf("test: %q, output format: %q", res.testName, format)
	cAnalyzer := NewConnlistAnalyzer(WithOutputFormat(format), WithFocusWorkload(focusWorkload))
	if exposureFlag {
		cAnalyzer = NewConnlistAnalyzer(WithOutputFormat(format), WithFocusWorkload(focusWorkload), WithExposureAnalysis())
	}
	res.analyzer = cAnalyzer
	res.dirPath = testutils.GetTestDirPath(dirName)
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
		exposureFlag     bool
	}{
		{
			name:             "giving_unsupported_output_format_option_should_return_fatal_error",
			dirName:          "onlineboutique",
			format:           "docx",
			errorStrContains: netpolerrors.FormatNotSupportedErrStr("docx"),
		},
		{
			name:             "unsupported_output_format_for_exposure_analysis_should_return_fatal_error",
			dirName:          "acs-security-demos",
			format:           "gif",
			errorStrContains: netpolerrors.FormatNotSupportedErrStr("gif"),
			exposureFlag:     true,
		},
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			preparedTest := prepareTest(tt.dirName, "", tt.format, tt.exposureFlag)
			connsRes, peersRes, err := preparedTest.analyzer.ConnlistFromDirPath(preparedTest.dirPath)

			require.Nil(t, err, tt.name)
			// "unable to decode ... connlist_output.json"
			require.Equal(t, len(preparedTest.analyzer.errors), 1, "expecting error since builder not able to parse connlist_output.json")
			require.NotEmpty(t, connsRes, notEmptyMsg)
			require.NotEmpty(t, peersRes, notEmptyMsg)

			out, err := preparedTest.analyzer.ConnectionsListToString(connsRes)
			require.Empty(t, out, tt.name)
			testutils.CheckErrorContainment(t, tt.name, tt.errorStrContains, err.Error())

			// re-run the test with new analyzer (to clear the analyzer.errors array )
			preparedTest = prepareTest(tt.dirName, "", tt.format, tt.exposureFlag)
			infos, _ := fsscanner.GetResourceInfosFromDirPath([]string{preparedTest.dirPath}, true, false)
			connsRes2, peersRes2, err2 := preparedTest.analyzer.ConnlistFromResourceInfos(infos)

			require.Nil(t, err2, tt.name)
			require.Empty(t, preparedTest.analyzer.errors, "expecting no errors from ConnlistFromResourceInfos")
			require.NotEmpty(t, connsRes2, notEmptyMsg)
			require.NotEmpty(t, peersRes2, notEmptyMsg)

			out, err2 = preparedTest.analyzer.ConnectionsListToString(connsRes)
			require.Empty(t, out, tt.name)
			testutils.CheckErrorContainment(t, tt.name, tt.errorStrContains, err2.Error())
		})
	}
}

var goodPathTests = []struct {
	testDirName      string
	outputFormats    []string
	focusWorkload    string
	exposureAnalysis bool
}{
	{
		testDirName:   "ipblockstest",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "onlineboutique",
		outputFormats: []string{output.JSONFormat, output.MDFormat, output.TextFormat},
	},
	{
		testDirName:   "onlineboutique_workloads",
		outputFormats: []string{output.CSVFormat, output.DOTFormat, output.TextFormat},
	},
	{
		testDirName:   "minikube_resources",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "online_boutique_workloads_no_ns",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "core_pods_without_host_ip",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "acs_security_frontend_demos",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "demo_app_with_routes_and_ingress",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "k8s_ingress_test",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "multiple_ingress_objects_with_different_ports",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "one_ingress_multiple_ports",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "one_ingress_multiple_services",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "acs-security-demos",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "acs-security-demos-with-netpol-list",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "test_with_named_ports",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "test_with_named_ports_changed_netpol",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "netpol-analysis-example-minimal",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "with_end_port_example",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "with_end_port_example_new",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "new_online_boutique",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "new_online_boutique_synthesis",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "multiple_topology_resources_1",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "multiple_topology_resources_2",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "multiple_topology_resources_3",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "multiple_topology_resources_4",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "minimal_test_in_ns",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "semanticDiff-same-topologies-old1",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "semanticDiff-same-topologies-old2",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "semanticDiff-same-topologies-old3",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "semanticDiff-same-topologies-new1",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "semanticDiff-same-topologies-new1a",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "semanticDiff-same-topologies-new2",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "semanticDiff-same-topologies-new3",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "semanticDiff-orig-topologies-no-policy",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "semanticDiff-orig-topologies-policy-a",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "semanticDiff-different-topologies-policy-a",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "semanticDiff-different-topologies-policy-b",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "ipblockstest_2",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "ipblockstest_3",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "ipblockstest_4",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "semanticDiff-different-topologies-policy-a-with-ipblock",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "semanticDiff-different-topologies-policy-b-with-ipblock",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "test_with_named_ports_changed_netpol_2",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "onlineboutique_workloads",
		focusWorkload: "emailservice",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "k8s_ingress_test",
		focusWorkload: "details-v1-79f774bdb9",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "acs-security-demos-added-workloads",
		focusWorkload: "backend/recommendation",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "acs-security-demos-added-workloads",
		focusWorkload: "asset-cache",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "acs-security-demos-added-workloads",
		focusWorkload: "frontend/asset-cache",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "acs-security-demos-added-workloads",
		focusWorkload: "ingress-controller",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:      "acs-security-demos",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "acs-security-demos",
		exposureAnalysis: true,
		// test with focus-workload that appears in exposure-analysis result
		focusWorkload: "frontend/webapp",
		outputFormats: ValidFormats,
	},
	{
		testDirName:      "acs-security-demos",
		exposureAnalysis: true,
		// test with focus-workload that does not appear in exposure-analysis result
		focusWorkload: "backend/catalog",
		outputFormats: ValidFormats,
	},
	{
		testDirName:      "exposure_allow_all_test",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_allow_all_in_cluster_test",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_allow_egress_deny_ingress_test",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_allow_ingress_deny_egress_test",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_matched_and_unmatched_rules_test",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_matched_and_unmatched_rules_test",
		exposureAnalysis: true,
		focusWorkload:    "hello-world/workload-a",
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_only_matched_rules_test",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_multiple_unmatched_rules_test",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_to_new_namespace_conn_and_entire_cluster",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_same_unmatched_rule_in_ingress_egress",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_with_no_netpols",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_egress_to_entire_cluster_with_named_ports",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_ingress_from_entire_cluster_with_named_ports",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_egress_with_named_port",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_to_namespace_with_multiple_labels_test",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_pod_exposed_only_to_representative_peers",
		exposureAnalysis: false,
		outputFormats:    []string{output.TextFormat},
	},
	{
		testDirName:      "exposure_test_pod_exposed_only_to_representative_peers",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_conn_entire_cluster_with_empty_selectors",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_conn_to_all_pods_in_a_new_ns",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_conn_with_new_pod_selector_and_ns_selector",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_conn_with_only_pod_selector",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_conn_with_pod_selector_in_any_ns",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "onlineboutique_workloads",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "onlineboutique_workloads",
		exposureAnalysis: true,
		focusWorkload:    "default/loadgenerator",
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "k8s_ingress_test_new",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "k8s_ingress_test_new",
		exposureAnalysis: true,
		focusWorkload:    "details-v1-79f774bdb9",
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "k8s_ingress_test",
		exposureAnalysis: true,
		focusWorkload:    "ratings-v1-b6994bb9",
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_minimal_netpol_analysis",
		exposureAnalysis: true,
		outputFormats:    []string{output.DOTFormat},
	},
	{
		// test that when the rule enable any-namespace with podSelector, a representative peer is created even
		// if there is a matching pod in a specific namespace
		testDirName:      "exposure_test_to_any_namespace_with_podSelector",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_conn_to_all_pods_in_an_existing_ns",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_conn_to_new_pod_in_an_existing_ns",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_conn_to_all_pods_in_an_existing_ns_with_ns_selector_only",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		// following test resources : contains two pods in different namespaces, and two policies, one for each namespace
		// first policy captures: hello-world/workload-a and exposes it on Ingress to all pods in backend namespace
		// second policy captures: backend/backend-app and denies all egress from it
		// so as result hello-world/workload-a is actually exposed to all backend pods except for backend-app
		// note: following exposure line in output :
		// `hello-world/workload-a[Deployment]      <=      backend/[all pods] : TCP 8050`
		// could have been more accurate with:
		// `hello-world/workload-a[Deployment]      <=      backend/[pods without app: backend-app] : TCP 8050`
		// but the goal is to hint where policy can be tightened, thus it is ok to ignore policies that capture
		// representative peers in the analysis

		testDirName:      "exposure_test_to_namespace_except_specific_pod",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	// tests on exposure with matchExpression selectors (generating representative peers from selectors with matchExpression
	// requires special handling)
	{
		testDirName:      "exposure_test_with_match_expression_not_in_op",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_with_match_expression_in_op",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_with_match_expression_exists_op",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_with_match_expression_does_not_exist_op",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_rule_with_multiple_match_expressions",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_with_different_rules_1",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_with_different_rules_2",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_with_different_rules_3",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_with_different_rules_4",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_with_different_rules_5",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_with_different_rules_6",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_with_multiple_policies_1", // one workload in manifests
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_with_multiple_policies_2", // two workloads in manifests, each policy captures one
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	// some exposure tests with matching expressions (from above) with also matching pod/s in the manifests
	{
		testDirName:      "exposure_test_egress_with_named_port_with_matching_pod",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_rule_with_multiple_match_expressions_with_matching_pod",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_with_different_rules_2_with_matching_pod",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_with_different_rules_3_with_matching_pod",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_with_different_rules_4_with_matching_pods",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_with_different_rules_5_with_matching_pods",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_with_different_rules_6_with_matching_pods",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_with_match_expression_does_not_exist_op_with_matching_pods",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_with_match_expression_exists_op_with_matching_pods",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_with_match_expression_in_op_with_matching_pod",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_with_match_expression_not_in_op_with_matching_pods",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_to_new_namespace_conn_and_entire_cluster_with_matching_pod",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_with_multiple_policies_1_with_matching_pod",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "exposure_test_different_but_equiv_rules",
		exposureAnalysis: true,
		outputFormats:    []string{output.DefaultFormat},
	},
	{
		// this test to emphasize why namespaces should be split with policies at the beginning,
		// if the namespaces are not split the analyzer will not recognize that there is a real pod in a real
		// namespace which exactly match the netpol's rule and will add an unnecessary exposure line in the results
		// hello-world/workload-a[Deployment]      <=      [namespace with {name=ns2}]/[pod with {app=b-app}] : All Connections
		testDirName:      "exposure_test_with_real_pod_and_namespace",
		exposureAnalysis: true,
		outputFormats:    []string{output.DefaultFormat},
	},
	{
		// in exposure-analysis : representative-peers are compared (to be removed) with real pods only.
		// in this example: we have a defined namespace `ns1` with a label {x:xval}
		// and we have a pod `app:app-1` in `ns1` and two different policies capturing this pod.
		// one policy has rule with : nil ns selector and pod selector {app: foo}
		// and the second policy has rule with : ns selector {x: xval} and pod selecotr {app: foo}
		// since we don't have a real pod in `ns1` with {app: foo};
		// we'll see two representative peers in the output
		// one in `ns1` and the second in any ns with {x:xval}
		testDirName:      "exposure_test_real_namespace_without_real_pod",
		exposureAnalysis: true,
		outputFormats:    []string{output.DefaultFormat},
	},
	{
		// this test has same namespace, pod and netpols  like the previous one `exposure_test_real_namespace_without_real_pod`
		// with a new pod in `ns1` with the {app:foo} label.
		// i.e. this real pod has pod and ns labels matching both rules, so we don't see any representative peer in the output
		testDirName:      "exposure_test_real_namespace_with_matching_pod",
		exposureAnalysis: true,
		outputFormats:    []string{output.DefaultFormat},
	},
	{
		// the netpol allows connection to pod-a on a named port "newport" with "protocol UDP",
		// but since the configuration of "pod-a" contains a port with same name but a different protocol,
		// i.e. there is no matching named port in the pod's configuration; then the output does not contain
		// a connection from new-pod to pod-a
		testDirName:   "netpol_named_port_test",
		outputFormats: []string{output.DefaultFormat},
	},
	{
		// the netpol allows connection to "pod-b" on multiple named-ports;
		// only some of the ports have a matching named-port + protocol in the pod's configuration
		// so we see only the successfully converted ports in the connlist output
		testDirName:   "netpol_named_port_test_2",
		outputFormats: []string{output.DefaultFormat},
	},
	// tests with adminNetworkPolicy
	{
		testDirName:   "anp_test_1_deny_traffic_at_cluster_level",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "anp_test_2_allow_traffic_at_cluster_level",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:   "anp_test_3_pass_traffic",
		outputFormats: []string{output.TextFormat},
	},
	{
		// Should Deny traffic from slytherin to gryffindor and
		// Deny traffic to slytherin from gryffindor respecting ANP with priority 50, ignoring ANP with priority 60
		testDirName:   "anp_test_4",
		outputFormats: ValidFormats,
	},
	{
		// Should support a pass-egress to slytherin from gryffindor for ANP and respect the match for network policy
		// And Dney ingress from slytherin to gryffindor - respecting the ANP ingress rule
		testDirName:   "anp_test_5",
		outputFormats: ValidFormats,
	},
	{
		// this test to ensure rule ordering is respected
		testDirName:   "anp_test_6",
		outputFormats: ValidFormats,
	},
	{
		// rules are similar to the ones from anp_test_6 but with swaps, so we expect some different results
		testDirName:   "anp_test_6_swapping_rules",
		outputFormats: []string{output.TextFormat},
	},
	{
		// this test to ensure rule ordering is respected
		testDirName:   "anp_test_7",
		outputFormats: ValidFormats,
	},
	{
		// rules are similar to the ones from anp_test_7 but with swaps, so we expect some different results
		testDirName:   "anp_test_7_swapping_rules",
		outputFormats: []string{output.TextFormat},
	},
	{
		// this test to ensure rule ordering is respected
		testDirName:   "anp_test_8",
		outputFormats: ValidFormats,
	},
	{
		// rules are similar to the ones from anp_test_8 but with swaps, so we expect some different results
		testDirName:   "anp_test_8_swapping_rules",
		outputFormats: []string{output.TextFormat},
	},
	{
		// this test to ensure rule ordering is respected, with both ingress and egress
		testDirName:   "anp_test_9",
		outputFormats: ValidFormats,
	},
	{
		// rules are similar to the ones from anp_test_9 but with swaps, so we expect some different results
		testDirName:   "anp_test_9_swapping_rules",
		outputFormats: []string{output.TextFormat},
	},
	{
		// this test to ensure rule ordering is respected
		testDirName:   "anp_test_10",
		outputFormats: ValidFormats,
	},
	{
		// rules are similar to the ones from anp_test_10 but with swaps, so we expect some different results
		testDirName:   "anp_test_10_swapping_rules",
		outputFormats: []string{output.TextFormat},
	},
	{
		// this test to ensure rule ordering is respected
		testDirName:   "anp_test_11",
		outputFormats: ValidFormats,
	},
	{
		// rules are similar to the ones from anp_test_11 but with swaps, so we expect some different results
		testDirName:   "anp_test_11_swapping_rules",
		outputFormats: []string{output.TextFormat},
	},
	{
		// this test to ensure rule ordering is respected
		testDirName:   "anp_test_12",
		outputFormats: ValidFormats,
	},
	{
		// rules are similar to the ones from anp_test_12 but with swaps, so we expect some different results
		testDirName:   "anp_test_12_swapping_rules",
		outputFormats: []string{output.TextFormat},
	},
	{
		// test with two ANPs selecting same subject (one is an ingress ANP the other is egress ANP)
		testDirName:   "anp_test_combining_test_6_and_test_10",
		outputFormats: []string{output.TextFormat},
	},
	{
		// test with multiple ANPs
		testDirName:   "anp_test_multiple_anps",
		outputFormats: ValidFormats,
	},
	{
		// test with an anp where ingress and egress sections are not fully matched,
		// need to consider intersection before collecting other policies conns
		testDirName:   "anp_test_ingress_egress_intersection",
		outputFormats: []string{output.TextFormat},
	},
	// tests involving BANPs
	{
		testDirName:   "anp_np_banp_core_test",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "anp_banp_core_test",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "anp_test_4_with_priority_chang_pass_to_banp",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "anp_with_banp_pass_test",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "anp_with_np_and_banp_pass_test",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "anp_with_np_pass_test",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "banp_test_core_egress_sctp_rules",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "banp_test_core_egress_sctp_swapping_rules",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "banp_test_core_egress_tcp_rules",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "banp_test_core_egress_tcp_swapping_rules",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "banp_test_core_egress_udp_rules",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "banp_test_core_egress_udp_swapping_rules",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "banp_test_core_gress_rules",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "banp_test_core_gress_swapping_rules",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "banp_test_core_ingress_sctp_rules",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "banp_test_core_ingress_sctp_swapping_rules",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "banp_test_core_ingress_tcp_rules",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "banp_test_core_ingress_tcp_swapping_rules",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "banp_test_core_ingress_udp_rules",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "banp_test_core_ingress_udp_swapping_rules",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "anp_with_banp_new_test",
		outputFormats: []string{output.DefaultFormat},
	},
	{
		testDirName:   "anp_demo",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "anp_banp_blog_demo",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "anp_and_banp_using_networks_test",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "anp_banp_test_with_named_port_matched",
		outputFormats: []string{output.DefaultFormat},
	},
	// anp tests that raise warnings too (@todo add unit test for warning messages!!)
	{
		testDirName:   "anp_and_banp_using_networks_and_nodes_test",
		outputFormats: []string{output.DefaultFormat},
	},
	{
		testDirName:   "anp_and_banp_using_networks_with_ipv6_test",
		outputFormats: []string{output.DefaultFormat},
	},
	{
		testDirName:   "anp_banp_test_multiple_warnings",
		outputFormats: []string{output.DefaultFormat},
	},
	{
		testDirName:   "anp_banp_test_with_named_port_unmatched",
		outputFormats: []string{output.DefaultFormat},
	},
	{
		testDirName:   "anp_test_with_empty_port_range",
		outputFormats: []string{output.DefaultFormat},
	},
	{
		testDirName:   "np_test_with_empty_port_range",
		outputFormats: []string{output.DefaultFormat},
	},
	{
		testDirName:   "anp_test_named_ports_multiple_peers",
		outputFormats: []string{output.DefaultFormat},
	},
}

func runParsedResourcesConnlistTests(t *testing.T, testList []examples.ParsedResourcesTest) {
	t.Helper()
	for i := 0; i < len(testList); i++ {
		test := &testList[i]
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			analyzer := NewConnlistAnalyzer(WithOutputFormat(test.OutputFormat))
			res, _, err := analyzer.connsListFromParsedResources(test.GetK8sObjects())
			require.Nil(t, err, test.TestInfo)
			out, err := analyzer.ConnectionsListToString(res)
			require.Nil(t, err, test.TestInfo)
			testutils.CheckActualVsExpectedOutputMatch(t, test.ExpectedOutputFileName, out,
				test.TestInfo, currentPkg)
		})
	}
}

func TestAllParsedResourcesConnlistTests(t *testing.T) {
	runParsedResourcesConnlistTests(t, examples.ANPConnectivityFromParsedResourcesTest)
	runParsedResourcesConnlistTests(t, examples.BANPConnectivityFromParsedResourcesTest)
	runParsedResourcesConnlistTests(t, examples.ANPWithNetPolV1FromParsedResourcesTest)
	runParsedResourcesConnlistTests(t, examples.BANPWithNetPolV1FromParsedResourcesTest)
	runParsedResourcesConnlistTests(t, examples.ANPWithBANPFromParsedResourcesTest)
}
