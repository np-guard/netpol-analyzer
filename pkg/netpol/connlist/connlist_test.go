/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connlist

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/np-guard/netpol-analyzer/pkg/internal/common"
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
		t.Run(tt.testDirName, func(t *testing.T) {
			t.Parallel()
			for _, format := range tt.outputFormats {
				testutils.SkipRunningSVGTestOnGithub(t, format)
				pTest := prepareTest(tt.testDirName, tt.focusWorkloads, tt.focusWorkloadPeers, tt.focusDirection, tt.focusConn,
					format, tt.exposureAnalysis)
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
		t.Run(tt.testDirName, func(t *testing.T) {
			t.Parallel()
			for _, format := range tt.outputFormats {
				testutils.SkipRunningSVGTestOnGithub(t, format)
				pTest := prepareTest(tt.testDirName, tt.focusWorkloads, tt.focusWorkloadPeers, tt.focusDirection, tt.focusConn,
					format, tt.exposureAnalysis)
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
			errorStrContains: netpolerrors.ConcatErrors(alerts.CidrErrTitle, alerts.InvalidCIDRAddr),
		},
		{
			name:             "Input_dir_has_netpol_with_bad_label_key_should_return_fatal_selector_error",
			dirName:          filepath.Join("bad_netpols", "subdir2"),
			errorStrContains: netpolerrors.ConcatErrors(alerts.SelectorErrTitle, alerts.InvalidKeyVal),
		},
		{
			name:             "Input_dir_has_netpol_with_bad_label_value_should_return_fatal_selector_error",
			dirName:          filepath.Join("bad_netpols", "subdir7"),
			errorStrContains: (alerts.SelectorErrTitle),
		},
		{
			name:             "Input_dir_has_netpol_with_invalid_rule_peer_should_return_fatal_rule_NetworkPolicyPeer_error",
			dirName:          filepath.Join("bad_netpols", "subdir3"),
			errorStrContains: netpolerrors.ConcatErrors(alerts.RulePeerErrTitle, alerts.CombinedRulePeerErrStr),
		},
		{
			name:             "Input_dir_has_netpol_with_empty_rule_peer_should_return_fatal_rule_NetworkPolicyPeer_error",
			dirName:          filepath.Join("bad_netpols", "subdir4"),
			errorStrContains: netpolerrors.ConcatErrors(alerts.RulePeerErrTitle, alerts.EmptyRulePeerErrStr),
		},
		{
			name:             "Input_dir_has_netpol_with_named_port_on_ipblock_peer_should_return_fatal_named_port_error",
			dirName:          filepath.Join("bad_netpols", "subdir6"),
			errorStrContains: netpolerrors.ConcatErrors(alerts.NamedPortErrTitle, alerts.ConvertNamedPortErrStr),
		},
		/*// input dir does not exist
		{
			name:             "Input_dir_does_not_exist_should_return_fatal_error_accessing_directory",
			dirName:          filepath.Join("bad_yamls", "subdir3"),
			errorStrContains: "does not exist", // TODO: actual msg: "the path ... does not exist"
		},*/
		// pods list issue - pods with same owner but different labels
		{
			name:             "Input_dir_has_pods_with_same_owner_name_w_different_labels_selected_by_policy_should_return_fatal_error",
			dirName:          "semanticDiff-same-topologies-illegal-podlist",
			errorStrContains: alerts.NotSupportedPodResourcesErrorStr("demo/cog-agents"),
		},
		{
			name:             "Input_dir_has_pods_with_same_owner_name_w_different_labels_selected_by_policy_should_return_fatal_error2",
			dirName:          "example_pods_w_same_owner_and_labels_gap_with_bad_match_expression",
			errorStrContains: alerts.NotSupportedPodResourcesErrorStr("default/internal-security"),
		},
		{
			name:             "Input_dir_has_pods_with_same_owner_name_w_different_labels_selected_by_policy_should_return_fatal_error3",
			dirName:          "example_w_err_pods_w_same_owner_and_labels_gap_anp",
			errorStrContains: alerts.NotSupportedPodResourcesErrorStr("default/internal-security"),
		},
		{
			name:             "Input_dir_has_two_netpols_with_same_name_in_a_namespace_should_return_fatal_error_of_existing_object",
			dirName:          "np_bad_path_test_1",
			errorStrContains: alerts.NPWithSameNameError("default/backend-netpol"),
		},
		{
			name:             "Input_dir_has_netpol_with_illegal_port_should_return_fatal_error",
			dirName:          "np_bad_path_test_2",
			errorStrContains: alerts.EndPortWithNamedPortErrStr,
		},
		{
			name:             "Input_dir_has_netpol_with_illegal_port_range_should_return_fatal_error",
			dirName:          "np_test_with_empty_port_range",
			errorStrContains: alerts.IllegalPortRangeError(10, 1),
		},
		// anp & banp bad path tests
		{
			name:             "Input_dir_has_two_admin_netpols_with_same_priority_should_return_fatal_error",
			dirName:          "anp_bad_path_test_1",
			errorStrContains: alerts.PriorityErrExplain,
		},
		{
			name:             "Input_dir_has_an_admin_netpol_with_invalid_priority_should_return_fatal_error",
			dirName:          "anp_bad_path_test_2",
			errorStrContains: alerts.PriorityValueErr("invalid-priority", 1001),
		},
		{
			name:             "Input_dir_has_two_admin_netpols_with_same_name_should_return_fatal_error",
			dirName:          "anp_bad_path_test_3",
			errorStrContains: alerts.ANPsWithSameNameErr("same-name"),
		},
		{
			name:             "Input_dir_has_an_admin_netpol_with_empty_subject_should_return_fatal_error",
			dirName:          "anp_bad_path_test_4",
			errorStrContains: alerts.OneFieldSetSubjectErr,
		},
		{
			name:             "Input_dir_has_an_admin_netpol_with_invalid_subject_should_return_fatal_error",
			dirName:          "anp_bad_path_test_5",
			errorStrContains: alerts.OneFieldSetSubjectErr,
		},
		{
			name:             "Input_dir_has_an_admin_netpol_with_an_empty_egress_rule_peer_should_return_fatal_error",
			dirName:          "anp_bad_path_test_6",
			errorStrContains: alerts.ANPEgressRulePeersErr,
		},
		{
			name:             "Input_dir_has_an_admin_netpol_with_an_invalid_egress_rule_peer_should_return_fatal_error",
			dirName:          "anp_bad_path_test_7",
			errorStrContains: alerts.OneFieldSetRulePeerErr,
		},
		{
			name:             "Input_dir_has_an_admin_netpol_with_an_invalid_egress_rule_port_should_return_fatal_error",
			dirName:          "anp_bad_path_test_8",
			errorStrContains: alerts.ANPPortsError,
		},
		{
			name:             "Input_dir_has_an_admin_netpol_with_an_invalid_egress_rule_action_should_return_fatal_error",
			dirName:          "anp_bad_path_test_9",
			errorStrContains: alerts.UnknownRuleActionErr,
		},
		{
			name:             "Input_dir_has_an_admin_netpol_missing_egress_rule_peer_should_return_fatal_error",
			dirName:          "anp_bad_path_test_10",
			errorStrContains: alerts.ANPEgressRulePeersErr,
		},
		{
			name:             "Input_dir_has_an_admin_netpol_missing_egress_rule_action_should_return_fatal_error",
			dirName:          "anp_bad_path_test_12",
			errorStrContains: alerts.UnknownRuleActionErr,
		},
		{
			name:             "Input_dir_has_an_admin_netpol_missing_ingress_rule_peer_should_return_fatal_error",
			dirName:          "anp_bad_path_test_14",
			errorStrContains: alerts.ANPIngressRulePeersErr,
		},
		{
			name:             "Input_dir_has_an_admin_netpol_with_an_empty_ingress_rule_peer_should_return_fatal_error",
			dirName:          "anp_bad_path_test_15",
			errorStrContains: alerts.ANPIngressRulePeersErr,
		},
		{
			name:             "Input_dir_has_an_admin_netpol_with_an_invalid_ingress_rule_peer_should_return_fatal_error",
			dirName:          "anp_bad_path_test_16",
			errorStrContains: alerts.OneFieldSetRulePeerErr,
		},
		{
			name:             "Input_dir_has_an_admin_netpol_with_an_invalid_ingress_rule_port_should_return_fatal_error",
			dirName:          "anp_bad_path_test_17",
			errorStrContains: alerts.ANPPortsError,
		},
		{
			name:             "Input_dir_has_an_admin_netpol_with_an_illegal_rule_port_range_should_return_fatal_error",
			dirName:          "anp_test_with_empty_port_range",
			errorStrContains: alerts.IllegalPortRangeError(10, 1),
		},
		{
			name:             "Input_dir_has_an_admin_netpol_with_an_invalid_ingress_rule_action_should_return_fatal_error",
			dirName:          "anp_bad_path_test_18",
			errorStrContains: alerts.UnknownRuleActionErr,
		},
		{
			name:             "Input_dir_has_an_admin_netpol_with_an_invalid_egress_cidr_peer_should_return_fatal_error",
			dirName:          "anp_bad_path_test_19",
			errorStrContains: alerts.InvalidCIDRAddr,
		},
		{
			name:             "Input_dir_has_admin_netpols_one_with_invalid_priority_should_return_fatal_error",
			dirName:          "anp_bad_path_test_20",
			errorStrContains: alerts.PriorityValueErr("invalid-priority", 1001),
		},
		{
			name:             "Input_dir_has_more_than_one_baseline_admin_netpol_should_return_fatal_error",
			dirName:          "banp_bad_path_test_1",
			errorStrContains: alerts.BANPAlreadyExists,
		},
		{
			name:             "Input_dir_has_baseline_admin_netpol_with_name_not_default_should_return_fatal_error",
			dirName:          "banp_bad_path_test_2",
			errorStrContains: alerts.BANPNameAssertion,
		},
		{
			name:             "Input_dir_has_baseline_admin_netpol_with_empty_subject_should_return_fatal_error",
			dirName:          "banp_bad_path_test_3",
			errorStrContains: alerts.OneFieldSetSubjectErr,
		},
		{
			name:             "Input_dir_has_baseline_admin_netpol_with_invalid_subject_should_return_fatal_error",
			dirName:          "banp_bad_path_test_4",
			errorStrContains: alerts.OneFieldSetSubjectErr,
		},
		{
			name:             "Input_dir_has_baseline_admin_netpol_with_an_empty_egress_rule_peer_should_return_fatal_error",
			dirName:          "banp_bad_path_test_5",
			errorStrContains: alerts.ANPEgressRulePeersErr,
		},
		{
			name:             "Input_dir_has_baseline_admin_netpol_with_missing_egress_rule_peer_should_return_fatal_error",
			dirName:          "banp_bad_path_test_6",
			errorStrContains: alerts.ANPEgressRulePeersErr,
		},
		{
			name:             "Input_dir_has_baseline_admin_netpol_with_an_invalid_egress_rule_peer_should_return_fatal_error",
			dirName:          "banp_bad_path_test_7",
			errorStrContains: alerts.OneFieldSetRulePeerErr,
		},
		{
			name:             "Input_dir_has_baseline_admin_netpol_with_an_invalid_egress_rule_action_should_return_fatal_error",
			dirName:          "banp_bad_path_test_8",
			errorStrContains: alerts.UnknownRuleActionErr,
		},
		{
			name:             "Input_dir_has_baseline_admin_netpol_with_an_invalid_egress_rule_port_should_return_fatal_error",
			dirName:          "banp_bad_path_test_9",
			errorStrContains: alerts.ANPPortsError,
		},
		{
			name:             "Input_dir_has_baseline_admin_netpol_with_missing_ingress_rule_peer_should_return_fatal_error",
			dirName:          "banp_bad_path_test_10",
			errorStrContains: alerts.ANPIngressRulePeersErr,
		},
		{
			name:             "Input_dir_has_baseline_admin_netpol_with_an_empty_ingress_rule_peer_should_return_fatal_error",
			dirName:          "banp_bad_path_test_11",
			errorStrContains: alerts.ANPIngressRulePeersErr,
		},
		{
			name:             "Input_dir_has_baseline_admin_netpol_with_an_invalid_ingress_rule_peer_should_return_fatal_error",
			dirName:          "banp_bad_path_test_12",
			errorStrContains: alerts.OneFieldSetRulePeerErr,
		},
		{
			name:             "Input_dir_has_baseline_admin_netpol_with_an_invalid_ingress_rule_port_should_return_fatal_error",
			dirName:          "banp_bad_path_test_13",
			errorStrContains: alerts.ANPPortsError,
		},
		{
			name:             "Input_dir_has_baseline_admin_netpol_with_an_invalid_ingress_rule_action_should_return_fatal_error",
			dirName:          "banp_bad_path_test_14",
			errorStrContains: alerts.UnknownRuleActionErr,
		},
		{
			name:             "Input_dir_has_baseline_admin_netpol_with_an_invalid_egress_cidr_peer_should_return_fatal_error",
			dirName:          "banp_bad_path_test_15",
			errorStrContains: alerts.InvalidCIDRAddr,
		},
		{
			name:             "Input_dir_has_two_namespaces_with_same_name_return_fatal_error",
			dirName:          "bad_path_namespace_with_same_name",
			errorStrContains: alerts.NSWithSameNameError("blue"),
		},
		{
			name:             "Input_udn_contains_invalid_value_for_key_topology_return_fatal_error",
			dirName:          "udn_bad_path_test_1",
			errorStrContains: alerts.InvalidKeyValue("blue/separate-namespace", "topology", "Layer4"),
		},
		{
			name:             "Input_udn_contains_mismatch_between_key_topology_and_actual_layer_return_fatal_error",
			dirName:          "udn_bad_path_test_2",
			errorStrContains: alerts.DisMatchLayerConfiguration("blue/separate-namespace", "Layer2"),
		},
		{
			name:             "Input_udn_contains_invalid_value_for_key_role_return_fatal_error",
			dirName:          "udn_bad_path_test_3",
			errorStrContains: alerts.InvalidKeyValue("blue/separate-namespace", "role", "Admin"),
		},
		{
			name:             "Input_udn_name_is_default_return_fatal_error",
			dirName:          "udn_bad_path_test_4",
			errorStrContains: alerts.UDNNameAssertion("blue/default"),
		},
		{
			name:             "Input_udn_is_in_default_namespace_return_fatal_error",
			dirName:          "udn_bad_path_test_5",
			errorStrContains: alerts.UDNNamespaceAssertion("namespace-scoped", "default"),
		},
		{
			name:             "Input_udn_is_in_openshift_namespace_return_fatal_error",
			dirName:          "udn_bad_path_test_6",
			errorStrContains: alerts.UDNNamespaceAssertion("namespace-scoped", "openshift-oc"),
		},
		{
			name:             "Input_namespace_has_two_primary_UDNs_return_fatal_error",
			dirName:          "udn_bad_path_test_7",
			errorStrContains: alerts.OnePrimaryUDNAssertion("blue", "blue/separate-namespace", "blue/namespace-scoped"),
		},
		{
			name:             "Input_namespace_selected_by_two_primary_CUDN_and_UDN_return_fatal_error",
			dirName:          "cudn_bad_test_1",
			errorStrContains: alerts.OnePrimaryUDNAssertion("red", "cudn-selecting-red-ns", "red/red-network"),
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			for _, apiToTest := range connlistTestedAPIS {
				analyzer, connsRes, peersRes, err := getAnalysisResFromAPI(apiToTest, tt.dirName, nil, nil, "")
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

func getAnalysisResFromAPI(apiName, dirName string, focusWorkloads, focusWorkloadPeers []string, focusDirection string) (
	analyzer *ConnlistAnalyzer, connsRes []Peer2PeerConnection, peersRes []Peer, err error) {
	pTest := prepareTest(dirName, focusWorkloads, focusWorkloadPeers, focusDirection, "", output.DefaultFormat, false)
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
		focusWorkloads      []string
		focusWorkloadPeers  []string
		focusDirection      string
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
			$ ./bin/netpol-analyzer list --dirpath tests/malformed_pod_example/
			2023/11/02 08:56:16 : err : in file: tests\malformed_pod_example\pod.yaml YAML document is malformed:
			 error for resource with kind: Pod , name: nginx , :  unrecognized type: int32
			2023/11/02 08:56:16 : no relevant Kubernetes workload resources found
			2023/11/02 08:56:16 no relevant Kubernetes network policy resources found


		*/
		{
			name:                "malformed_yaml_unrecognized_type_int32",
			dirName:             "malformed_pod_example",
			firstErrStrContains: alerts.UnrecognizedValType, // netpolerrors.MalformedYamlDocErrorStr
			emptyRes:            true,
		},
		{
			name:                "malformed_yaml_cannot_restore_slice_from_map",
			dirName:             "malformed-pod-example-2",
			firstErrStrContains: alerts.SliceFromMapErr, // netpolerrors.MalformedYamlDocErrorStr
			emptyRes:            false,
		},
		{
			name:                "input_dir_with_focusworkload_that_does_not_exist_should_get_warning",
			dirName:             "onlineboutique_workloads",
			focusWorkloads:      []string{"abcd"},
			firstErrStrContains: alerts.WorkloadDoesNotExistErrStr("abcd"),
			emptyRes:            true,
		},
		{
			name:                "input_dir_with_focusworkload_ns_and_name_that_does_not_exist_should_get_warning",
			dirName:             "onlineboutique_workloads",
			focusWorkloads:      []string{"default/abcd"},
			firstErrStrContains: alerts.WorkloadDoesNotExistErrStr("default/abcd"),
			emptyRes:            true,
		},
		{
			name:                "input_dir_with_focusworkload_from_list_that_does_not_exist_should_get_warning",
			dirName:             "anp_banp_blog_demo",
			focusWorkloads:      []string{"myfoo", "abcd"},
			firstErrStrContains: alerts.WorkloadDoesNotExistErrStr("abcd"),
			emptyRes:            false, // only one focus-workload does not exist
		},
		{
			name:                "input_dir_with_multiple_focusworkloads_that_do_not_exist_should_get_warnings",
			dirName:             "anp_banp_blog_demo",
			focusWorkloads:      []string{"myfriend", "abcd"},
			firstErrStrContains: alerts.WorkloadDoesNotExistErrStr("myfriend"),
			emptyRes:            true, // all focus-workloads do not exist - empty connlist
		},
		{
			name:                "input_dir_with_multiple_focusworkloads-peers_that_do_not_exist_should_get_warnings",
			dirName:             "anp_banp_blog_demo",
			focusWorkloads:      []string{"myfoo"},
			focusWorkloadPeers:  []string{"myfo", "mike"},
			firstErrStrContains: alerts.WorkloadDoesNotExistErrStr("myfo"),
			emptyRes:            true, // all focus-workloads peers do not exist - empty connlist
		},
		{
			name:                "input_dir_with_multiple_focusworkloads-peers_that_some_exist_should_get_warning_and_connlist_not_empty",
			dirName:             "anp_banp_blog_demo",
			focusWorkloads:      []string{"myfoo"},
			focusWorkloadPeers:  []string{"mybaz", "mike"},
			focusDirection:      common.EgressFocusDirection,
			firstErrStrContains: alerts.WorkloadDoesNotExistErrStr("mike"),
			emptyRes:            false, // some focus-workload-peers exist
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			for _, apiToTest := range connlistTestedAPIS {
				analyzer, connsRes, peersRes, err := getAnalysisResFromAPI(apiToTest, tt.dirName, tt.focusWorkloads,
					tt.focusWorkloadPeers, tt.focusDirection)
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
			errorStrContains: alerts.PathNotExistErr, // netpolerrors.ErrGettingResInfoFromDir
		},
		{
			name:             "empty_dir_with_no_yamls_or_json_files",
			dirName:          filepath.Join("bad_yamls", "subdir2"),
			errorStrContains: alerts.UnknownFileExtensionErr, // netpolerrors.ErrGettingResInfoFromDir
		},
		{
			name:             "bad_JSON_missing_kind", // this err is fatal here only because dir has no other resources
			dirName:          "malformed-pod-example-4",
			errorStrContains: alerts.MissingObjectErr, // kind is missing in pod json, netpolerrors.ErrGettingResInfoFromDir
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			analyzer, connsRes, peersRes, err := getAnalysisResFromAPI(DirPathFunc, tt.dirName, nil, nil, "")
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
	}{
		{
			name:             "irrelevant_JSON_file_unable_to_decode",
			dirName:          "onlineboutique",
			errorStrContains: alerts.UnmarshalErr, // netpolerrors.FailedReadingFileErrorStr
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			analyzer, connsRes, peersRes, err := getAnalysisResFromAPI(DirPathFunc, tt.dirName, nil, nil, "")
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
		focusDirection              string
		focusworkloads              []string
		focusWorkloadPeers          []string
		exposure                    bool
		explain                     bool
		explainOnly                 string
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
			name:                        "input_admin_policy_contains_named_port_with_networks_should_get_warning",
			dirName:                     "anp_test_named_ports_multiple_peers",
			expectedWarningsStrContains: []string{alerts.WarnNamedPortIgnoredForIP},
		},
		{
			name:                        "using_focus_direction_without_focus_workload",
			dirName:                     "anp_test_named_ports_multiple_peers",
			focusDirection:              common.IngressFocusDirection,
			expectedWarningsStrContains: []string{alerts.WarnIgnoredWithoutFocusWorkload},
		},
		{
			name:                        "using_focus_workload_peer_without_focus_workload",
			dirName:                     "anp_test_named_ports_multiple_peers",
			focusWorkloadPeers:          []string{"ns1/pod1"},
			expectedWarningsStrContains: []string{alerts.WarnIgnoredWithoutFocusWorkload},
		},
		{
			name:                        "using_exposure_with_focus_workload_peer_and_focus_workload",
			dirName:                     "anp_test_named_ports_multiple_peers",
			focusworkloads:              []string{"ns3/pod1"},
			focusWorkloadPeers:          []string{"ns1/pod1"},
			exposure:                    true,
			expectedWarningsStrContains: []string{alerts.WarnIgnoredExposure(focusworkloadStr, focusWorkloadPeerStr)},
		},
		{
			name:                        "using_explain_only_without_explain",
			dirName:                     "anp_test_named_ports_multiple_peers",
			explainOnly:                 common.ExplainOnlyAllow,
			expectedWarningsStrContains: []string{alerts.WarnIgnoredWithoutExplain},
		},
		{
			name:                        "using_exposure_with_explain_and_explain_only",
			dirName:                     "anp_test_named_ports_multiple_peers",
			explain:                     true,
			explainOnly:                 common.ExplainOnlyDeny,
			exposure:                    true,
			expectedWarningsStrContains: []string{alerts.WarnIgnoredExposure(explainStr, explainOnlyStr)},
		},
		{
			name:                        "using_secondary_udn_should_warn_that_not_supported_yet",
			dirName:                     "udn_warning_test_1",
			expectedWarningsStrContains: []string{alerts.NotSupportedUDNRole("green/namespace-scoped")},
		},
		{
			name:                        "udn_in_not_existing_namespace_should_warn_that_udn_is_ignored",
			dirName:                     "udn_warning_test_2",
			expectedWarningsStrContains: []string{alerts.WarnMissingNamespaceOfUDN("separate-namespace", "blue")},
		},
		{
			name:                        "udn_in_ns_without_label_should_warn_that_udn_is_ignored",
			dirName:                     "udn_warning_test_3",
			expectedWarningsStrContains: []string{alerts.WarnNamespaceDoesNotSupportUDN("namespace-scoped", "green")},
		},
		{
			name:                        "input_resources_contain_virt_launcher_pod_should_warn_that_it_is_ignored",
			dirName:                     "udn_and_vms_test_5",
			expectedWarningsStrContains: []string{alerts.WarnIgnoredVirtLauncherPod("foo/virt-launcher-fedora-apricot-pike-81-qr48r")},
		},
		{
			name:                        "cudn_selecting_a_ns_without_label_should_warn_that_selection_is_ignored",
			dirName:                     "cudn_test_3",
			expectedWarningsStrContains: []string{alerts.WarnCudnSelectsNsWithoutPrimaryUDNLabel("entire-cluster-cudn", "yellow-namespace")},
		},
		{
			name:                        "cudn_selector_has_no_matches",
			dirName:                     "cudn_warning_test_1",
			expectedWarningsStrContains: []string{alerts.EmptyCUDN("no-selection")},
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tLogger := testutils.NewTestLogger()
			opts := []ConnlistAnalyzerOption{WithLogger(tLogger), WithFocusDirection(tt.focusDirection),
				WithFocusWorkloadPeerList(tt.focusWorkloadPeers), WithFocusWorkloadList(tt.focusworkloads),
				WithExplainOnly(tt.explainOnly)}
			if tt.exposure {
				opts = append(opts, WithExposureAnalysis())
			}
			if tt.explain {
				opts = append(opts, WithExplanation())
			}
			_, _, err := getConnlistFromDirPathRes(opts, tt.dirName)
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
			expectedResultLen:    43,
			extractedLineExample: "kube-system/calico-node[DaemonSet] => kube-system/calico-node[DaemonSet] : All Connections",
		},
		{
			name:                 "connlist_of_dir_does_not_contain_any_line_of_connections_from_workload_to_itself",
			dirName:              "ipblockstest",
			expectedResultLen:    470,
			extractedLineExample: "kube-system/calico-node[DaemonSet] => kube-system/calico-node[DaemonSet] : All Connections",
		},
	}
	for _, tt := range cases {
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
		analyzerOptions = append(analyzerOptions, WithFocusWorkloadList([]string{focusWorkload}))
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

func prepareTest(dirName string, focusWorkloads, focusWorkloadPeers []string, focusDirection, focusConn, format string,
	exposureFlag bool) preparedTest {
	res := preparedTest{}
	res.testName, res.expectedOutputFileName = testutils.ConnlistTestNameByTestArgs(dirName,
		strings.Join(focusWorkloads, testutils.Underscore),
		strings.Join(focusWorkloadPeers, testutils.Underscore), focusDirection, focusConn, format, exposureFlag)
	res.testInfo = fmt.Sprintf("test: %q, output format: %q", res.testName, format)
	opts := []ConnlistAnalyzerOption{WithOutputFormat(format), WithFocusWorkloadList(focusWorkloads), WithFocusDirection(focusDirection),
		WithFocusWorkloadPeerList(focusWorkloadPeers), WithFocusConnection(focusConn)}
	if exposureFlag {
		opts = append(opts, WithExposureAnalysis())
	}
	res.analyzer = NewConnlistAnalyzer(opts...)
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			preparedTest := prepareTest(tt.dirName, nil, nil, "", "", tt.format, tt.exposureFlag)
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
			preparedTest = prepareTest(tt.dirName, nil, nil, "", "", tt.format, tt.exposureFlag)
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
	testDirName            string
	outputFormats          []string
	focusWorkloads         []string
	focusWorkloadPeers     []string
	focusDirection         string
	focusConn              string
	exposureAnalysis       bool
	supportedOnLiveCluster bool
}{
	{
		testDirName:            "ipblockstest",
		outputFormats:          []string{output.TextFormat},
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "onlineboutique",
		outputFormats:          []string{output.JSONFormat, output.MDFormat, output.TextFormat},
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "onlineboutique",
		outputFormats:          []string{output.MDFormat, output.TextFormat},
		exposureAnalysis:       true,
		supportedOnLiveCluster: true,
	},
	{
		testDirName:   "onlineboutique_workloads",
		outputFormats: []string{output.CSVFormat, output.DOTFormat, output.TextFormat},
	},
	{
		testDirName:            "minikube_resources",
		outputFormats:          []string{output.TextFormat},
		supportedOnLiveCluster: true,
	},
	{
		testDirName:   "online_boutique_workloads_no_ns",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:            "core_pods_without_host_ip",
		outputFormats:          []string{output.TextFormat},
		supportedOnLiveCluster: true,
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
		testDirName:            "test_with_named_ports",
		outputFormats:          []string{output.TextFormat},
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "test_with_named_ports_changed_netpol",
		outputFormats:          []string{output.TextFormat},
		supportedOnLiveCluster: true,
	},
	{
		testDirName:   "netpol-analysis-example-minimal",
		outputFormats: ValidFormats,
	},
	{
		testDirName:            "with_end_port_example",
		outputFormats:          []string{output.TextFormat},
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "with_end_port_example_new",
		outputFormats:          []string{output.TextFormat},
		supportedOnLiveCluster: true,
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
		testDirName:            "multiple_topology_resources_1",
		outputFormats:          []string{output.TextFormat},
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "multiple_topology_resources_2",
		outputFormats:          []string{output.TextFormat},
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "multiple_topology_resources_3",
		outputFormats:          []string{output.TextFormat},
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "multiple_topology_resources_4",
		outputFormats:          []string{output.TextFormat},
		supportedOnLiveCluster: true,
	},
	{
		testDirName:   "minimal_test_in_ns",
		outputFormats: []string{output.TextFormat},
	},
	{
		testDirName:            "semanticDiff-same-topologies-old1",
		outputFormats:          []string{output.TextFormat},
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "semanticDiff-same-topologies-old2",
		outputFormats:          []string{output.TextFormat},
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "semanticDiff-same-topologies-old3",
		outputFormats:          []string{output.TextFormat},
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "semanticDiff-same-topologies-new1",
		outputFormats:          []string{output.TextFormat},
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "semanticDiff-same-topologies-new1a",
		outputFormats:          []string{output.TextFormat},
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "semanticDiff-same-topologies-new2",
		outputFormats:          []string{output.TextFormat},
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "semanticDiff-same-topologies-new3",
		outputFormats:          []string{output.TextFormat},
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "semanticDiff-orig-topologies-no-policy",
		outputFormats:          []string{output.TextFormat},
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "semanticDiff-orig-topologies-policy-a",
		outputFormats:          []string{output.TextFormat},
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "semanticDiff-different-topologies-policy-a",
		outputFormats:          []string{output.TextFormat},
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "semanticDiff-different-topologies-policy-b",
		outputFormats:          []string{output.TextFormat},
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "ipblockstest_2",
		outputFormats:          []string{output.TextFormat},
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "ipblockstest_3",
		outputFormats:          []string{output.TextFormat},
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "ipblockstest_4",
		outputFormats:          []string{output.TextFormat},
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "semanticDiff-different-topologies-policy-a-with-ipblock",
		outputFormats:          []string{output.TextFormat},
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "semanticDiff-different-topologies-policy-b-with-ipblock",
		outputFormats:          []string{output.TextFormat},
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "test_with_named_ports_changed_netpol_2",
		outputFormats:          []string{output.TextFormat},
		supportedOnLiveCluster: true,
	},
	{
		testDirName:    "onlineboutique_workloads",
		focusWorkloads: []string{"emailservice"},
		outputFormats:  []string{output.TextFormat},
	},
	{
		testDirName:    "k8s_ingress_test",
		focusWorkloads: []string{"details-v1-79f774bdb9"},
		outputFormats:  []string{output.TextFormat},
	},
	{
		testDirName:    "acs-security-demos-added-workloads",
		focusWorkloads: []string{"backend/recommendation"},
		outputFormats:  []string{output.TextFormat},
	},
	{
		testDirName:    "acs-security-demos-added-workloads",
		focusWorkloads: []string{"backend/recommendation"},
		focusDirection: common.IngressFocusDirection,
		outputFormats:  []string{output.TextFormat},
	},
	{
		testDirName:    "acs-security-demos-added-workloads",
		focusWorkloads: []string{"backend/recommendation"},
		focusDirection: common.EgressFocusDirection,
		outputFormats:  []string{output.TextFormat},
	},
	{
		testDirName:    "acs-security-demos-added-workloads",
		focusWorkloads: []string{"asset-cache"},
		outputFormats:  []string{output.TextFormat},
	},
	{
		testDirName:    "acs-security-demos-added-workloads",
		focusWorkloads: []string{"frontend/asset-cache"},
		outputFormats:  []string{output.TextFormat},
	},
	{
		testDirName:    "acs-security-demos-added-workloads",
		focusWorkloads: []string{"ingress-controller"},
		outputFormats:  []string{output.TextFormat},
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
		focusWorkloads: []string{"frontend/webapp"},
		outputFormats:  ValidFormats,
	},
	{
		testDirName:      "acs-security-demos",
		exposureAnalysis: true,
		// test with focus-workload that appears in exposure-analysis result
		focusWorkloads: []string{"frontend/webapp"},
		focusDirection: common.IngressFocusDirection,
		outputFormats:  ValidFormats,
	},
	{
		testDirName:      "acs-security-demos",
		exposureAnalysis: true,
		// test with focus-workload that appears in exposure-analysis result
		focusWorkloads: []string{"frontend/webapp"},
		focusDirection: common.EgressFocusDirection,
		outputFormats:  ValidFormats,
	},
	{
		testDirName:      "acs-security-demos",
		exposureAnalysis: true,
		// test with focus-workload that does not appear in exposure-analysis result
		focusWorkloads: []string{"backend/catalog"},
		outputFormats:  ValidFormats,
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
		focusWorkloads:   []string{"hello-world/workload-a"},
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
		focusWorkloads:   []string{"default/loadgenerator"},
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
		focusWorkloads:   []string{"details-v1-79f774bdb9"},
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "k8s_ingress_test",
		exposureAnalysis: true,
		focusWorkloads:   []string{"ratings-v1-b6994bb9"},
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
		testDirName:            "anp_banp_blog_demo",
		outputFormats:          ValidFormats,
		supportedOnLiveCluster: true,
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
		testDirName:   "anp_test_named_ports_multiple_peers",
		outputFormats: []string{output.DefaultFormat},
	},
	{
		// AdminNetworkPolicy: exposes all pods in namespace hello-world to representative-peers in a "slytherin" labeled namespace
		// on a TCP-80 connection on both egress and ingress
		// NetworkPolicy : denies all for hello-world/workload-a
		// Output: hello-world/workload-a is exposed to all pods in the "slytherin" namespace (on both egress and ingress);
		// however hello-world/workload-b is exposed to entire-cluster and external-ips on all connections on both egress and ingress
		testDirName:      "exposure_test_with_anp_1",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		// AdminNetworkPolicy: exposes all pods in namespace hello-world to representative-peers in a "slytherin" labeled namespace
		// on a TCP-80 connection on both egress and ingress
		// NetworkPolicy : restricts hello-world/workload-a connections to and from representative peers in a "gryffindor" labeled namespace
		// Output: hello-world/workload-a is exposed to all pods in the "slytherin" namespace and all pods in "gryffindor";
		// however hello-world/workload-b is exposed to entire-cluster and external-ips on all connections on both egress and ingress
		testDirName:      "exposure_test_with_anp_2_w_np",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		// AdminNetworkPolicy: Passes TCP80 between hello-world and slytherin namespaces on both ingress and egress
		// BaselineAdminNetworkPolicy: denies any internal ingress to hello-world on TCP80
		// Output: all pods of hello-world are exposed on egress on all-connections to whole world
		// On Ingress hello-world pods are exposed externally to all-connections, and internally to all conns but TCP80
		testDirName:      "exposure_test_with_anp_3_w_banp",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		// AdminNetworkPolicy: exposes all pods in namespace hello-world to all-namespaces on a TCP-80 connection on both egress and ingress
		// NetworkPolicy : denies all for hello-world/workload-a
		// Output: hello-world/workload-a is exposed to all-namespaces on TCP80 (on both egress and ingress);
		// however hello-world/workload-b is exposed to entire-cluster and external-ips on all connections on both egress and ingress
		testDirName:      "exposure_test_with_anp_4_entire_cluster_example",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		// AdminNetworkPolicy: denies TCP80 connection between hello-world and all-namespaces on both ingress-egress
		// Output: all pods in hello-world are exposed externally to all conns
		// and exposed internally on all-conns but TCP80 on both ingress and egress
		testDirName:      "exposure_test_with_anp_5_entire_cluster_example",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		// AdminNetworkPolicy: Passes TCP80 connection between hello-world to all-namespace on ingress and egress
		// NetworkPolicy: restricts hello-world/workload-a conns with all-namespaces to some ports (block TCP80 on ingress)
		// Output: hello-world/workload-a is exposed to entire-cluster to the ports mentioned in the NetworkPolicy only;
		// however hello-world/workload-b is exposed to entire-cluster and external-ips on all connections on both egress and ingress
		testDirName:      "exposure_test_with_anp_6_entire_cluster_example",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		// AdminNetworkPolicy: ingress ANP that exposes all workloads in namespace: hello-world with PASS rule (on all-conns from entire-cluster)
		// i.e. ANP protect on Ingress both hello-world/workload-a and hello-world/workload-b
		// BaselineAdminNetworkPolicy : denies all internal ingress for hello-world/workload-a only
		// In the Output: hello-world/workload-a is not exposed to ingress from entire-cluster;
		// however hello-world/workload-b is exposed to entire-cluster on ingress from entire-cluster
		testDirName:      "exposure_test_with_anp_7_w_banp",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		// AdminNetworkPolicy: with a prior deny rule that denies TCP9090 to a representative-peer; and another rule
		// that allows all conns to entire cluster.
		// in the output we see exposure to the representative peer on all conns but TCP9090
		// and also we see that the peer is exposed to entire-cluster on all conns
		// this example shows that the output is not defined in peers resolution and the `entire-cluster` may implicitly
		// exclude some peers in the cluster.
		testDirName:      "exposure_test_with_anp_8",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		// AdminNetworkPolicy: with a prior deny rule that denies all conns to a real-peer; and another rule
		// that allows all conns to entire cluster.
		// in the connlist output we see that there is no connection from hello-world/workload-a to hello-world/workload-b
		// since its denied by egress ANP
		// and in the exposure output we see that the peer is exposed on egress to entire-cluster on all conns
		// in the graph this is clear that there is no conns between the real-peers
		// this example shows that the output is not defined in peers resolution and the `entire-cluster` may implicitly
		// exclude some peers in the cluster (in this case a real-peer).
		testDirName:      "exposure_test_with_anp_10_with_real_pod",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		// AdminNetworkPolicy: with a prior deny rule that denies all conns to a representative-peer; and another rule
		// that allows all conns to entire cluster.
		// in the exposure output we see:
		// 1. there is No Connections from hello-world/workload-a to the representative-peer
		// 2. that the peer is exposed on egress to entire-cluster on all conns
		// this example shows that the output is not defined in peers resolution and the `entire-cluster` may implicitly
		// exclude some peers in the cluster
		// in this case a representative-peer - the output with No Connections, was added to help the user see that
		// it is excluded from entire-cluster
		testDirName:      "exposure_test_with_anp_9",
		exposureAnalysis: true,
		outputFormats:    ValidFormats,
	},
	{
		// AdminNetworkPolicy : exposes the hello-world/workload-a to entire-cluster on namedPort on both ingress and egress
		// NetworkPolicy denies all on hello-world/workload-a (so is exposed only to the named-ports from ANP)
		// Note that: A rule with NamedPort of ANP does not specify the protocol; protocol is determined by the destination's configuration
		// On the ingress exposure output, since the dst is hello-world/workload-a itself, the namedPort is converted
		// according to the pod's configuration
		// but on egress exposure, we see that the potential is to the namedPort (protocol may be any)
		// In the connlist output - we see how the named-port is determined by the dest's configuration
		testDirName:      "exposure_test_with_anp_11_with_named_port",
		outputFormats:    []string{output.DefaultFormat},
		exposureAnalysis: true,
	},
	{
		// AdminNetworkPolicy : exposes the hello-world/workload-a to other hello-world pods on TCP9090 on egress and ingress
		// BaselineAdminNetworkPolicy: denies TCP9090 on egress and ingress between hello-world/workload-a and entire-cluster
		// Output: internal conns with hello-world/workload-a is allowed on all conns but TCP9090, except for pods
		// in hello-world, where all conns are allowed
		testDirName:      "exposure_test_with_anp_12",
		outputFormats:    []string{output.DefaultFormat},
		exposureAnalysis: true,
	},
	{
		// exposure test with ANP and BANP with rules matching existing peers and
		// rules not matching existing peers
		testDirName:      "exposure_test_with_anp_13",
		outputFormats:    ValidFormats,
		exposureAnalysis: true,
	},
	{
		// exposure test with ANP and BANP with matchExpressions (different order in the rule, but same)
		testDirName:      "exposure_test_with_anp_14",
		outputFormats:    ValidFormats,
		exposureAnalysis: true,
	},
	{
		// exposure test with multiple ANPs
		testDirName:      "exposure_test_with_anp_15",
		outputFormats:    []string{output.DefaultFormat},
		exposureAnalysis: true,
	},
	{
		// exposure test with excluded labeled pod from any namespace
		testDirName:      "exposure_test_with_anp_16",
		outputFormats:    ValidFormats,
		exposureAnalysis: true,
	},
	// tests with multiple workloads
	{
		testDirName:            "anp_banp_blog_demo",
		focusWorkloads:         []string{"myfoo", "mybar"},
		outputFormats:          ValidFormats,
		supportedOnLiveCluster: true,
	},
	{
		testDirName:      "acs-security-demos",
		exposureAnalysis: true,
		focusWorkloads:   []string{"backend/checkout", "frontend/webapp"},
		outputFormats:    ValidFormats,
	},
	{
		testDirName:      "acs-security-demos",
		exposureAnalysis: true,
		focusWorkloads:   []string{"backend/checkout", "frontend/webapp"},
		focusDirection:   common.EgressFocusDirection,
		outputFormats:    ValidFormats,
	},
	{
		testDirName:        "acs-security-demos",
		focusWorkloads:     []string{"backend/checkout", "frontend/webapp"},
		focusWorkloadPeers: []string{"backend/recommendation"},
		outputFormats:      ValidFormats,
	},
	{
		testDirName:        "acs-security-demos",
		focusWorkloads:     []string{"checkout"},
		focusWorkloadPeers: []string{"webapp"},
		focusDirection:     common.IngressFocusDirection,
		outputFormats:      ValidFormats,
	},
	{
		testDirName:        "acs-security-demos",
		focusWorkloads:     []string{"checkout", "reports"},
		focusWorkloadPeers: []string{"recommendation", "catalog"},
		focusDirection:     common.EgressFocusDirection,
		outputFormats:      ValidFormats,
	},
	{
		testDirName:   "anp_demo",
		focusConn:     "udp-52",
		outputFormats: ValidFormats,
	},
	{
		testDirName:      "anp_demo",
		focusConn:        "udp-52",
		outputFormats:    ValidFormats,
		exposureAnalysis: true,
	},
	{
		testDirName:      "anp_demo",
		focusConn:        "tcp-8080",
		outputFormats:    ValidFormats,
		exposureAnalysis: true,
		focusWorkloads:   []string{"harry-potter"},
		focusDirection:   common.EgressFocusDirection,
	},
	{
		testDirName:            "anp_banp_blog_demo",
		focusConn:              "udp-52",
		outputFormats:          []string{output.DefaultFormat},
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "anp_banp_blog_demo",
		focusWorkloads:         []string{"mybar"},
		focusWorkloadPeers:     []string{"mybaz"},
		focusDirection:         common.EgressFocusDirection,
		outputFormats:          []string{output.DefaultFormat},
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "anp_banp_blog_demo",
		exposureAnalysis:       true,
		outputFormats:          []string{output.DefaultFormat},
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "anp_banp_blog_demo",
		focusWorkloads:         []string{"mybar"},
		focusDirection:         common.EgressFocusDirection,
		exposureAnalysis:       true,
		outputFormats:          []string{output.DefaultFormat},
		supportedOnLiveCluster: true,
	},
	{
		// in following example we have 2 pods which belong to same owner;
		// the pods have different labels;
		// however, since there are no policies in the input resources
		// a connectivity report is generated (the labels diff does not affect the analysis)
		testDirName:            "example_pods_w_same_owner_and_labels_gap_no_policy",
		outputFormats:          []string{output.DefaultFormat},
		supportedOnLiveCluster: true,
	},
	{
		// in following example we have 2 pods which belong to same owner; the pods have different labels;
		// however, since the policy rule selector (which selects those pods) uses a label-selector which is same in both pods
		// i.e. not from the gap:
		// a connectivity report is generated (the labels diff does not affect the analysis)
		testDirName:            "example_pods_w_same_owner_and_labels_gap_with_policy_selector_not_in_gap",
		outputFormats:          []string{output.DefaultFormat},
		supportedOnLiveCluster: true,
	},
	{
		// in following example we have 2 pods which belong to same owner; the pods have different labels;
		// however, since the admin-policy subject (which selects those pods) uses a label-selector which is same in both pods
		// i.e. not from the gap:
		// a connectivity report is generated (the labels diff does not affect the analysis)
		testDirName:            "example_pods_w_same_owner_and_labels_gap_anp_good",
		outputFormats:          []string{output.DefaultFormat},
		supportedOnLiveCluster: true,
	},
	{
		// in following example we have 2 pods which belong to same owner; the pods have different labels;
		// however, since the policy (which selects those pods) uses a matchExpression with exists opertaor (no matter what the value is)
		// a connectivity report is generated (the labels diff does not affect the analysis)
		testDirName:            "example_pods_w_same_owner_and_labels_gap_with_good_match_expression",
		outputFormats:          []string{output.DefaultFormat},
		supportedOnLiveCluster: true,
	},
	{
		// in following example we have 2 pods which belong to same owner; the pods have different labels;
		// however, since the baseline-admin-policy (which selects those pods) uses a label-selector which is same in both pods
		// a connectivity report is generated (the labels diff does not affect the analysis)
		testDirName:            "example_pods_w_same_owner_and_labels_gap_banp_good",
		outputFormats:          []string{output.DefaultFormat},
		supportedOnLiveCluster: true,
	},
	{
		// in following example we have 2 pods which belong to same owner; the pods have different labels;
		// however, since the policy (which selects those pods) uses a matchExpression with in opertaor
		// and both gap-values
		// a connectivity report is generated (the labels diff does not affect the analysis)
		testDirName:            "example_pods_w_same_owner_and_labels_gap_with_good_match_expression2",
		outputFormats:          []string{output.DefaultFormat},
		supportedOnLiveCluster: true,
	},
	{
		// With user-defined networks, the need for complex network policies are eliminated because isolation
		// can be achieved by grouping workloads in different networks.
		testDirName:   "udn_test_1",
		outputFormats: ValidFormats,
	},
	{
		// user-defined network with network-policy in an isolated network
		testDirName:   "udn_test_2",
		outputFormats: ValidFormats,
	},
	{
		// user-defined network with network-policy in an isolated network
		testDirName:   "udn_test_2",
		outputFormats: ValidFormats,
		focusConn:     "tcp-90",
	},
	{
		// one user-defined network with network-policy.
		// 2 regular pod networks (in namespaces without UDN)
		// AdminNetworkPolicy that enables egress from pods with specific label - pods in the udn still isolated
		testDirName:   "udn_test_3",
		outputFormats: ValidFormats,
	},
	{
		// one user-defined network with network-policy.
		// 2 namespaces in regular pod networks (without UDN)
		// Networkpolicy in the regular pod networks that enables egress to whole world - pods in the udn still isolated
		testDirName:   "udn_test_4",
		outputFormats: ValidFormats,
	},
	{
		// a test with UDN and Ingress-Controller; external ingress to a service in a UDN are allowed if the pod's ports match
		testDirName:   "udn_with_ingress_controller",
		outputFormats: ValidFormats,
	},
	{
		// a test with UDN and Ingress-Controller; external ingress to a service in a UDN are allowed if the pod's ports match
		// this test contains two pods in the UDN, one matches the Ingress and service's ports and the second not matching them
		testDirName:   "udn_with_ingress_controller_two_pods",
		outputFormats: ValidFormats,
	},
	// tests involving udn(s) and virtual-machine workloads
	{
		testDirName:   "udn_and_vms_test_1",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "udn_and_vms_test_2",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "udn_and_vms_test_3",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "udn_and_vms_test_4",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "udn_and_vms_test_5",
		outputFormats: ValidFormats,
	},
	{
		// virtual-machine(s) test in the default namespace (without-udn)
		testDirName:   "virtual_machines_example",
		outputFormats: ValidFormats,
	},
	{
		// a test with UDN having a VM and Ingress-Controller; external ingress ports to a service in a UDN are allowed to the VM
		testDirName:   "udn_with_vm_and_ingress_controller",
		outputFormats: ValidFormats,
	},
	{
		// resource: https://github.com/maiqueb/fosdem2025-p-udn/tree/main/manifests/cluster-wide-network
		testDirName:   "cudn_test_1",
		outputFormats: ValidFormats,
	},
	{
		// cudn selects all namespaces, all of them have the required label to define ns as a udn
		testDirName:   "cudn_test_2",
		outputFormats: ValidFormats,
	},
	{
		// cudn selects all namespaces, but not all of the namespaces has the required label in their spec,
		// so those will not belong to the cudn
		testDirName:   "cudn_test_3",
		outputFormats: ValidFormats,
	},
	{
		// resource: https://github.com/epheo/blog/tree/e0e83c121b6b225fd38c6443bf19b7b5a0f7687d/articles/openshift-layer2-udn
		// involves udn and cudn
		testDirName:   "cudn_test_4",
		outputFormats: ValidFormats,
	},
	{
		// resource: https://github.com/tssurya/kubecon-eu-2025-london-udn-workshop/tree
		// /4d6be99a0ee1ede775a505c35026ee75c799228d/manifests/udns-with-pods
		// cudn + udns + networkpolicy
		testDirName:   "cudn_test_5",
		outputFormats: ValidFormats,
	},
	{
		testDirName:   "cudn_test_6",
		outputFormats: ValidFormats,
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
