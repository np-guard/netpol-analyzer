/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package diff

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
	"github.com/np-guard/netpol-analyzer/pkg/internal/output"
	"github.com/np-guard/netpol-analyzer/pkg/internal/testutils"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/fsscanner"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/alerts"
)

const ResourceInfosFunc = "ConnDiffFromResourceInfos"
const DirPathFunc = "ConnDiffFromDirPaths"
const currentPkg = "diff"
const atRef1 = "at ref1: "
const atRef2 = "at ref2: "

var diffTestedAPIS = []string{ResourceInfosFunc, DirPathFunc}

//////////////////////////////////good path tests/////////////////////////////////////////////////////////////////////////

// TestDiff tests the output for valid input resources, for both apis (ConnDiffFromResourceInfos , ConnDiffFromDirPaths)
func TestDiff(t *testing.T) {
	t.Parallel()
	for _, tt := range goodPathTests {
		for _, format := range tt.formats {
			testutils.SkipRunningSVGTestOnGithub(t, format)
			for _, apiFunc := range diffTestedAPIS {
				pTest := prepareTest(tt.firstDirName, tt.secondDirName, format, apiFunc, "")
				t.Run(pTest.testName, func(t *testing.T) {
					t.Parallel()
					diffRes, err := getAnalysisResFromAPI(apiFunc, pTest)
					require.Nil(t, err, pTest.testInfo)
					actualOutput, err := pTest.analyzer.ConnectivityDiffToString(diffRes)
					require.Nil(t, err, pTest.testInfo)
					testutils.CheckActualVsExpectedOutputMatch(t, pTest.expectedOutputFileName, actualOutput,
						pTest.testInfo, currentPkg)
				})
			}
		}
	}
}

/////////////////////////////////////bad path tests /////////////////////////////////////////////////////////////////////////////////

// fatal errors common for both interfaces (ConnDiffFromDirPaths & ConnDiffFromResourceInfos)
//--------------------------------------------------------------------------------------------

// TestDiffAnalyzeFatalErrors tests fatal errors returned while computing the connectivity diff
func TestDiffAnalyzeFatalErrors(t *testing.T) {
	t.Parallel()
	for _, tt := range commonBadPathTestsFatalErr {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			for _, apiFunc := range diffTestedAPIS {
				pTest := prepareTest(tt.ref1, tt.ref2, output.DefaultFormat, apiFunc, tt.name)
				diffRes, err := getAnalysisResFromAPI(apiFunc, pTest)
				require.Empty(t, diffRes, "test: %q, apiFunc: %q", tt.name, apiFunc)
				testutils.CheckErrorContainment(t, pTest.testInfo, tt.errorStrContains, err.Error())
				require.Equal(t, 1, len(pTest.analyzer.errors))
				testutils.CheckErrorContainment(t, pTest.testInfo, tt.errorStrContains, pTest.analyzer.errors[0].Error().Error())
			}
		})
	}
}

// severe errors and warnings, common for both interfaces (ConnDiffFromDirPaths & ConnDiffFromResourceInfos)
//--------------------------------------------------------------------------------------------

// TODO: test stopOnErr here?

func TestDiffAnalyzerSevereErrorsAndWarnings(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name                string
		ref1                string
		ref2                string
		containedErrOrWarns []string
		emptyRes            bool
		onlyDirPathsAPI     bool
	}{
		{
			name: "first_input_dir_has_no_k8s_resources_should_return_severe_error",
			ref1: filepath.Join("bad_yamls", "not_a_k8s_resource.yaml"),
			ref2: "ipblockstest", // no warnings, nor any severe/fatal errors
			containedErrOrWarns: []string{
				alerts.UnableToDecodeErr, // "at dir 1" currently printed to log, but not attached to err itself
				atRef1 + netpolerrors.NoK8sWorkloadResourcesFoundErrorStr,
				atRef1 + netpolerrors.NoK8sNetworkPolicyResourcesFoundErrorStr,
			},
			onlyDirPathsAPI: true,
			emptyRes:        false, // expecting diff result because ref2 has resources
		},
		{
			// same test as the one above, this time with both apis - thus "unable to decode" not included,
			// as issued by the builder
			name: "first_input_dir_has_no_k8s_resources_should_return_severe_error",
			ref1: filepath.Join("bad_yamls", "not_a_k8s_resource.yaml"),
			ref2: "ipblockstest", // no warnings, nor any severe/fatal errors
			containedErrOrWarns: []string{
				atRef1 + netpolerrors.NoK8sWorkloadResourcesFoundErrorStr,
				atRef1 + netpolerrors.NoK8sNetworkPolicyResourcesFoundErrorStr,
			},
			emptyRes: false, // expecting diff result because ref2 has resources
		},
		{
			name: "first_input_dir_has_no_netpols_should_get_no_relevant_k8s_policies_found",
			ref1: "k8s_ingress_test",
			ref2: "k8s_ingress_test_new",
			containedErrOrWarns: []string{
				atRef1 + netpolerrors.NoK8sNetworkPolicyResourcesFoundErrorStr,
			},
			emptyRes: false, // expecting diff result, both dirs have resources
		},
		{
			name: "in_second_input_dir_network_policies_block_ingress_conns_to_a_workload_should_get_warning_msg",
			ref1: "acs-security-demos",
			ref2: "acs-security-demos-new",
			containedErrOrWarns: []string{
				atRef2 + alerts.BlockedIngressWarning("Route", "frontend/asset-cache", "frontend/asset-cache[Deployment]"),
			},
			emptyRes: false, // expecting diff result, both dirs have resources
		},

		/*{
			// dirty directory, includes 3 severe errors
			// when running without stopOnError we expect to see 6 severe errors (3 for each dir flag)
			// but when running with stopOnError we expect to see only 1 , and then stops
			name:                           "both_input_dirs_contain_malformed_yaml_files_should_return_severe_errors",
			ref1:                           "dirty",
			ref2:                           "dirty",
			firstErrStrContains:            "YAML document is malformed",
			expectedErrNumWithoutStopOnErr: 6,
			expectedErrNumWithStopOnErr:    1,
		},*/
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			for _, apiFunc := range diffTestedAPIS {
				if tt.onlyDirPathsAPI && apiFunc != DirPathFunc {
					continue
				}
				pTest := prepareTest(tt.ref1, tt.ref2, output.DefaultFormat, apiFunc, tt.name)
				diffRes, err := getAnalysisResFromAPI(apiFunc, pTest)
				if tt.emptyRes {
					require.Empty(t, diffRes, pTest.testInfo)
				} else {
					require.NotEmpty(t, diffRes, pTest.testInfo)
				}

				// not a fatal err, thus require err is nil
				require.Nil(t, err, pTest.testInfo)

				// check containment of all expected err/warn strings in analyzer.errors
				for _, errStr := range tt.containedErrOrWarns {
					checkIfErrStrContained(t, pTest, errStr)
				}
			}
		})
	}
}

func checkIfErrStrContained(t *testing.T, pTest *preparedTest, errStr string) {
	hasErr := false
	for _, err := range pTest.analyzer.errors {
		if strings.Contains(err.Error().Error(), errStr) {
			hasErr = true
		}
	}
	require.True(t, hasErr, "err containment check for %s with err: %s", pTest.testInfo, errStr)
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Test errs/warnings unique for ConnDiffFromDirPaths only (issued by the resources builder)
// ----------------------------------------------------------------------------------------------

func TestErrorsConnDiffFromDirPathOnly(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name                string
		ref1                string
		ref2                string
		containedErrOrWarns []string
		emptyRes            bool
		onlyDirPathsAPI     bool
		isFatal             bool
	}{
		{
			name: "both_input_dirs_do_not_exist",
			ref1: "some_dir",
			ref2: "some_other_dir",
			containedErrOrWarns: []string{
				// [the path "tests/some_dir" does not exist, the path "tests/some_other_dir" does not exist]
				"[the path ", "some_dir", alerts.PathNotExistErr, "some_other_dir",
			},
			emptyRes: true, // fatal err
			isFatal:  true,
		},
		{
			name: "first_dir_does_not_exist_and_second_dir_has_json_that_cannot_be_decoded",
			ref1: "some_dir",
			ref2: "acs-security-demos",
			containedErrOrWarns: []string{
				// [the path "tests/some_other_dir" does not exist, unable to decode "tests\\acs-security-demos\\connlist_output.json":
				// json: cannot unmarshal array into Go value of type unstructured.detector]
				"[the path ", "some_dir", alerts.PathNotExistErr, alerts.UnableToDecodeErr, "connlist_output.json",
			},
			emptyRes: true, // fatal err
			isFatal:  true,
		},
		{
			name: "dir_has_json_that_cannot_be_decoded_and_dir1_ref2_are_the_same",
			ref1: "acs-security-demos",
			ref2: "acs-security-demos",
			containedErrOrWarns: []string{
				// at ref1: error reading file: unable to decode ...
				// at ref2: error reading file: unable to decode ...
				// "at dir" is only attached to the log msg and not to the returned err obj
				alerts.UnableToDecodeErr, "connlist_output.json", netpolerrors.FailedReadingFileErrorStr,
			},
			emptyRes: false, // no diff, but ConnectivityDiff contains non-changed conns
			isFatal:  false,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pTest := prepareTest(tt.ref1, tt.ref2, output.DefaultFormat, DirPathFunc, tt.name)
			diffRes, err := getAnalysisResFromAPI(DirPathFunc, pTest)
			if tt.emptyRes {
				require.Empty(t, diffRes, pTest.testInfo)
			} else {
				require.NotEmpty(t, diffRes, pTest.testInfo)
			}

			if !tt.isFatal {
				// not a fatal err, thus require err is nil
				require.Nil(t, err, pTest.testInfo)
			} else {
				// fatal err - the expected err should be returned
				for _, expectedErrStr := range tt.containedErrOrWarns {
					testutils.CheckErrorContainment(t, pTest.testInfo, expectedErrStr, err.Error())
				}
			}

			// check containment of all expected err/warn strings in analyzer.errors
			for _, errStr := range tt.containedErrOrWarns {
				checkIfErrStrContained(t, pTest, errStr) // checks pTest.analyzer.errors
			}
		})
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////

// TestDiffOutputFatalErrors tests fatal errors returned while writing the diff to string in given output format
func TestDiffOutputFatalErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name             string
		ref1             string
		ref2             string
		format           string
		errorStrContains string
	}{
		{
			name:             "giving_unsupported_output_format_option_should_return_fatal_error",
			ref1:             "onlineboutique_workloads",
			ref2:             "onlineboutique_workloads_changed_netpols",
			format:           "png",
			errorStrContains: netpolerrors.FormatNotSupportedErrStr("png"),
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			for _, apiFunc := range diffTestedAPIS {
				pTest := prepareTest(tt.ref1, tt.ref2, tt.format, apiFunc, tt.name)
				connsDiff, err := getAnalysisResFromAPI(apiFunc, pTest)
				require.Nil(t, err, pTest.testInfo)
				require.NotEmpty(t, connsDiff, pTest.testInfo)
				res, err := pTest.analyzer.ConnectivityDiffToString(connsDiff)
				require.Empty(t, res, pTest.testInfo)
				testutils.CheckErrorContainment(t, pTest.testInfo, tt.errorStrContains, err.Error())
			}
		})
	}
}

// TODO: change to be one of the set from good path tests
func TestDiffOutputWithArgNamesOption(t *testing.T) {
	ref1 := "onlineboutique_workloads"
	ref2 := "onlineboutique_workloads_changed_netpols"
	for _, format := range ValidDiffFormats {
		testutils.SkipRunningSVGTestOnGithub(t, format)
		analyzer := NewDiffAnalyzer(WithOutputFormat(format), WithArgNames("old", "new"))
		diffRes, err := analyzer.ConnDiffFromDirPaths(testutils.GetTestDirPath(ref1), testutils.GetTestDirPath(ref2))
		require.Nil(t, err)
		require.NotEmpty(t, diffRes)
		res, err := analyzer.ConnectivityDiffToString(diffRes)
		require.Nil(t, err)
		testNamePrefix := "TsetOutputWithArgNamesOption_"
		testName, outFileName := testutils.DiffTestNameByTestArgs(ref1, ref2, format)
		testName = testNamePrefix + testName
		outFileName = testNamePrefix + outFileName
		testutils.CheckActualVsExpectedOutputMatch(t, outFileName, res, testName, currentPkg)
	}
}

type preparedTest struct {
	testName               string
	testInfo               string
	firstDirPath           string
	secondDirPath          string
	expectedOutputFileName string
	analyzer               *DiffAnalyzer
}

func prepareTest(firstDir, secondDir, format, apiName, testNameStr string) *preparedTest {
	var testName, expectedOutputFileName string
	if testNameStr != "" {
		testName = testNameStr
		expectedOutputFileName = ""
	} else {
		testName, expectedOutputFileName = testutils.DiffTestNameByTestArgs(firstDir, secondDir, format)
	}

	return &preparedTest{
		testName:               testName,
		expectedOutputFileName: expectedOutputFileName,
		testInfo:               fmt.Sprintf("test: %q, output format: %q, api func: %q", testName, format, apiName),
		analyzer:               NewDiffAnalyzer(WithOutputFormat(format)),
		firstDirPath:           testutils.GetTestDirPath(firstDir),
		secondDirPath:          testutils.GetTestDirPath(secondDir),
	}
}

func getAnalysisResFromAPI(apiName string, pTest *preparedTest) (diffRes ConnectivityDiff, err error) {
	switch apiName {
	case ResourceInfosFunc:
		infos1, _ := fsscanner.GetResourceInfosFromDirPath([]string{pTest.firstDirPath}, true, false)
		infos2, _ := fsscanner.GetResourceInfosFromDirPath([]string{pTest.secondDirPath}, true, false)
		diffRes, err = pTest.analyzer.ConnDiffFromResourceInfos(infos1, infos2)
	case DirPathFunc:
		diffRes, err = pTest.analyzer.ConnDiffFromDirPaths(pTest.firstDirPath, pTest.secondDirPath)
	}
	return diffRes, err
}

var goodPathTests = []struct {
	firstDirName  string
	secondDirName string
	formats       []string
}{
	{
		// description:
		// **changed netpols: default/frontend-netpol, default/adservice-netpol, default/checkoutservice-netpol,
		// 		default/cartservice-netpol, default/currencyservice-netpol, default/emailservice-netpol
		// **added netpols : default/redis-cart-netpol
		firstDirName:  "onlineboutique_workloads",
		secondDirName: "onlineboutique_workloads_changed_netpols",
		formats:       ValidDiffFormats,
	},
	{
		// description:
		// **changed netpols: default/frontend-netpol, default/adservice-netpol, default/checkoutservice-netpol,
		// 		default/cartservice-netpol, default/currencyservice-netpol, default/emailservice-netpol
		// **added netpols : default/redis-cart-netpol
		// **added workloads: default/unicorn
		firstDirName:  "onlineboutique_workloads",
		secondDirName: "onlineboutique_workloads_changed_netpols_and_workloads",
		formats:       ValidDiffFormats,
	},
	{
		// description:
		// **added workloads: default/unicorn
		firstDirName:  "onlineboutique_workloads",
		secondDirName: "onlineboutique_workloads_changed_workloads",
		formats:       ValidDiffFormats,
	},
	{
		// description:
		// **changed netpols: default/frontend-netpol
		// **added Ingress: default/onlineboutique-ingress
		firstDirName:  "onlineboutique_workloads",
		secondDirName: "onlineboutique_workloads_with_ingress",
		formats:       []string{output.CSVFormat},
	},
	{
		// description:
		// ** changed Ingress:  default/ingress-policy
		// ** added netpols: default/productpage-netpol, default/details-netpol, default/reviews-netpol,
		//		 default/ratings-netpol
		// **added workloads: default/unicorn
		firstDirName:  "k8s_ingress_test",
		secondDirName: "k8s_ingress_test_new",
		formats:       ValidDiffFormats,
	},
	{
		// description:
		// **changed workloads : backend/catalog (removed port)
		// **added workloads: external/unicorn
		// **removed workloads: payments/mastercard-processor
		// **changed netpols: frontend/asset-cache-netpol (blocked ingress), backend/catalog-netpol, backend/reports-netpol,
		//			backend/shipping-netpol, frontend/webapp-netpol,
		firstDirName:  "acs-security-demos",
		secondDirName: "acs-security-demos-new",
		formats:       ValidDiffFormats,
	},
	{
		// description:
		// **removed Routes: frontend/asset-cache, frontend/webapp
		firstDirName:  "acs-security-demos",
		secondDirName: "acs-security-demos-no-routes",
		formats:       []string{output.DefaultFormat},
	},
	{
		// description:
		// **removed Ingress: ingressworld/ingress-2
		// **added Route: ingressworld/route-1
		firstDirName:  "multiple_ingress_objects_with_different_ports",
		secondDirName: "multiple_ingress_objects_with_different_ports_new",
		formats:       ValidDiffFormats,
	},
	{
		// description:
		// **changed netpols : default/limit-app1-traffic
		// **in first dir connlist, default/deployment1 does not appear even it exists, since the netpol denies all traffic from/to it
		// in second dir , the netpol limits the ingress of it , so it appears in the diff
		firstDirName:  "deny_all_to_from_a_deployment",
		secondDirName: "deny_all_to_from_a_deployment_changed_netpol",
		formats:       []string{output.DefaultFormat},
	},
	{
		// description:
		// **added workloads: frontend/blog, payments/visa-processor-v2, zeroday/zeroday
		// **added routes: frontend/blog, zeroday/zeroday
		// **added netpols: frontend/blog-netpol, payments/visa-processor-v2-netpol, zeroday/zeroday-netpol,
		// zeroday/default-deny-in-namespace-zeroday
		// **changed netpols : payments/gateway-netpol,
		firstDirName:  "acs-security-demos",
		secondDirName: "acs-security-demos-added-workloads",
		formats:       ValidDiffFormats,
	},
	{
		// description:
		// **changed netpols : default/backend-netpol,
		firstDirName:  "netpol-analysis-example-minimal",
		secondDirName: "netpol-diff-example-minimal",
		formats:       ValidDiffFormats,
	},
	{
		// description:
		// **removed netpol: enable-all-protocols-with-all-ports
		// **added netpol: enable-all-traffic
		firstDirName:  "with_end_port_example",
		secondDirName: "with_end_port_example_new",
		formats:       ValidDiffFormats,
	},
	{
		// description:
		// **changed netpol: kube-system-dummy-to-ignore/ingress-based-on-named-ports
		firstDirName:  "test_with_named_ports",
		secondDirName: "test_with_named_ports_changed_netpol",
		formats:       []string{output.DefaultFormat},
	},
	{
		// description:
		// **changed netpols: demo/ui-to-command, demo/query-to-ui
		firstDirName:  "multiple_topology_resources_1",
		secondDirName: "multiple_topology_resources_2",
		formats:       []string{output.DefaultFormat},
	},
	{
		// description:
		// **added netpol: default/policy-from2-to1
		firstDirName:  "multiple_topology_resources_3",
		secondDirName: "multiple_topology_resources_4",
		formats:       []string{output.DefaultFormat},
	},
	{
		// description:
		// **changed netpols: limited egress in all policies , and limited ingress for loadgenerator
		firstDirName:  "new_online_boutique",
		secondDirName: "new_online_boutique_synthesis",
		formats:       []string{output.DefaultFormat},
	},
	{
		// description:
		// **changed netpols: demo/ui-to-command, demo/query-to-ui
		firstDirName:  "semanticDiff-same-topologies-old1",
		secondDirName: "semanticDiff-same-topologies-new1",
		formats:       []string{output.DefaultFormat},
	},
	{
		// description:
		// **changed netpols: demo/ui-to-command, demo/query-to-ui
		firstDirName:  "semanticDiff-same-topologies-old1",
		secondDirName: "semanticDiff-same-topologies-new1a",
		formats:       []string{output.DefaultFormat},
	},
	{
		// description:
		// **changed netpols: demo/ui-to-command
		firstDirName:  "semanticDiff-same-topologies-old2",
		secondDirName: "semanticDiff-same-topologies-new2",
		formats:       []string{output.DefaultFormat},
	},
	{
		// description:
		// **changed netpols: demo/query-to-ui
		// **removed netpols: demo/capture-ui
		// **added netpols: demo/capture-query
		firstDirName:  "semanticDiff-same-topologies-old3",
		secondDirName: "semanticDiff-same-topologies-new3",
		formats:       []string{output.DefaultFormat},
	},
	{
		// description:
		// **added netpols: default/policy-from2-to1
		firstDirName:  "semanticDiff-orig-topologies-no-policy",
		secondDirName: "semanticDiff-orig-topologies-policy-a",
		formats:       []string{output.DefaultFormat},
	},
	{
		// description:
		// **added ns: namespace-b
		// **removed ns: namespace-a
		// **removed pods: default/pod-3, default/pod-4
		// **added pods: default/pod-5, default/pod-6
		// **removed netpol: policy-from1-to2
		// **added netpol: policy-from2-to1
		firstDirName:  "semanticDiff-different-topologies-policy-a",
		secondDirName: "semanticDiff-different-topologies-policy-b",
		formats:       []string{output.DefaultFormat},
	},
	{
		// description:
		// **added ns: namespace-a
		// **removed ns: namespace-b
		// **added pods: default/pod-3, default/pod-4
		// **removed pods: default/pod-5, default/pod-6
		// **removed netpol: policy-from2-to1
		// **added netpol: policy-from1-to2
		firstDirName:  "semanticDiff-different-topologies-policy-b",
		secondDirName: "semanticDiff-different-topologies-policy-a",
		formats:       []string{output.DefaultFormat},
	},
	{
		// description:
		// **different topologies
		// **different policies
		firstDirName:  "semanticDiff-same-topologies-old1",
		secondDirName: "semanticDiff-different-topologies-policy-a",
		formats:       []string{output.DefaultFormat},
	},
	{
		// description:
		// **changed netpols: kube-system/enable-from-ipblock-to-isolated-by-tier
		firstDirName:  "ipblockstest",
		secondDirName: "ipblockstest_2",
		formats:       []string{output.DefaultFormat},
	},
	{
		// description:
		// **changed netpols: kube-system/enable-from-ipblock-to-isolated-by-tier
		firstDirName:  "ipblockstest",
		secondDirName: "ipblockstest_3",
		formats:       []string{output.DefaultFormat},
	},
	{
		// description:
		// **changed netpols: kube-system/enable-from-ipblock-to-isolated-by-tier
		firstDirName:  "ipblockstest_2",
		secondDirName: "ipblockstest_3",
		formats:       []string{output.DefaultFormat},
	},
	{
		// description:
		// **changed netpols: kube-system/enable-from-ipblock-to-isolated-by-tier
		firstDirName:  "ipblockstest",
		secondDirName: "ipblockstest_4",
		formats:       []string{output.DefaultFormat},
	},
	{
		// description:
		// **added ns: namespace-a
		// **removed ns: namespace-b
		// **added pods: default/pod-3, default/pod-4
		// **removed pods: default/pod-5, default/pod-6
		// **removed netpol: default/policy-from2-to1, default/policy-from-ip-block-to1
		// **added netpol: default/policy-from1-to2, default/policy-from-ip-block-to2
		firstDirName:  "semanticDiff-different-topologies-policy-a-with-ipblock",
		secondDirName: "semanticDiff-different-topologies-policy-b-with-ipblock",
		formats:       []string{output.DefaultFormat},
	},
	{
		// description:
		// **removed netpol: kube-system/ingress-based-on-named-ports
		// **added netpol: kube-system/ingress-based-on-port-number
		firstDirName:  "test_with_named_ports_changed_netpol_2",
		secondDirName: "test_with_named_ports_changed_netpol_3",
		formats:       []string{output.DefaultFormat},
	},
	{
		// description:
		// **changed netpols: anp : ingress-udp to ingress-udp-rules-swap
		// swapped some rules in the ANP to see different results, as rules orders must be respected
		firstDirName:  "anp_test_6",
		secondDirName: "anp_test_6_swapping_rules",
		formats:       ValidDiffFormats,
	},
	{
		// description:
		// **changed netpols: anp : ingress-tcp to ingress-tcp-with-swapped-rules
		// swapped some rules in the ANP to see different results, as rules orders must be respected
		firstDirName:  "anp_test_7",
		secondDirName: "anp_test_7_swapping_rules",
		formats:       ValidDiffFormats,
	},
	{
		// description:
		// **changed netpols: anp : ingress-sctp to ingress-sctp-with-swapped-rules
		// swapped some rules in the ANP to see different results, as rules orders must be respected
		firstDirName:  "anp_test_8",
		secondDirName: "anp_test_8_swapping_rules",
		formats:       ValidDiffFormats,
	},
	{
		// description:
		// **changed netpols: anp : gress-rules to gress-rules-with-swapped-rules
		// swapped some rules in the ANP to see different results, as rules orders must be respected
		firstDirName:  "anp_test_9",
		secondDirName: "anp_test_9_swapping_rules",
		formats:       ValidDiffFormats,
	},
	{
		// description:
		// **changed netpols: anp : egress-udp to egress-udp-with-swapped-rules
		// swapped some rules in the ANP to see different results, as rules orders must be respected
		firstDirName:  "anp_test_10",
		secondDirName: "anp_test_10_swapping_rules",
		formats:       ValidDiffFormats,
	},
	{
		// description:
		// **changed netpols: anp : egress-tcp to egress-tcp-with-swapped-rules
		// swapped some rules in the ANP to see different results, as rules orders must be respected
		firstDirName:  "anp_test_11",
		secondDirName: "anp_test_11_swapping_rules",
		formats:       ValidDiffFormats,
	},
	{
		// description:
		// **changed netpols: anp : egress-sctp to egress-sctp-with-swapped-rules
		// swapped some rules in the ANP to see different results, as rules orders must be respected
		firstDirName:  "anp_test_12",
		secondDirName: "anp_test_12_swapping_rules",
		formats:       ValidDiffFormats,
	},
	{
		// description:
		// **changed netpols: anp : priority of ANP : `old-priority-60` changed to 40
		// so it is now taking precedence on ANP: `priority-50-example`; and conns will be passed
		// BANP : a banp was added
		firstDirName:  "anp_test_4",
		secondDirName: "anp_test_4_with_priority_chang_pass_to_banp",
		formats:       ValidDiffFormats,
	},
	{
		// description:
		// **removed netpols: netpol : "allow-gress-from-to-slytherin-to-gryffindor"
		// so now ANP conns are passed to BANP;
		// denies conns between slytherin and gryffindor; no further restrictions on other conns from/to gryffindor.
		firstDirName:  "anp_np_banp_core_test",
		secondDirName: "anp_banp_core_test",
		formats:       ValidDiffFormats,
	},
	{
		// description:
		// in banp default swapped allow rules from first dir with deny rules in second dir;
		// so results should be changed as rules order must be respected
		firstDirName:  "banp_test_core_egress_sctp_rules",
		secondDirName: "banp_test_core_egress_sctp_swapping_rules",
		formats:       ValidDiffFormats,
	},
	{
		// description:
		// in banp default swapped allow rules from first dir with deny rules in second dir;
		// so results should be changed as rules order must be respected
		firstDirName:  "banp_test_core_egress_tcp_rules",
		secondDirName: "banp_test_core_egress_tcp_swapping_rules",
		formats:       ValidDiffFormats,
	},
	{
		// description:
		// in banp default swapped allow rules from first dir with deny rules in second dir;
		// so results should be changed as rules order must be respected
		firstDirName:  "banp_test_core_egress_udp_rules",
		secondDirName: "banp_test_core_egress_udp_swapping_rules",
		formats:       ValidDiffFormats,
	},
	{
		// description:
		// in banp default swapped allow rules from first dir with deny rules in second dir;
		// so results should be changed as rules order must be respected
		firstDirName:  "banp_test_core_gress_rules",
		secondDirName: "banp_test_core_gress_swapping_rules",
		formats:       ValidDiffFormats,
	},
	{
		// description:
		// in banp default swapped allow rules from first dir with deny rules in second dir;
		// so results should be changed as rules order must be respected
		firstDirName:  "banp_test_core_ingress_sctp_rules",
		secondDirName: "banp_test_core_ingress_sctp_swapping_rules",
		formats:       ValidDiffFormats,
	},
	{
		// description:
		// in banp default swapped allow rules from first dir with deny rules in second dir;
		// so results should be changed as rules order must be respected
		firstDirName:  "banp_test_core_ingress_tcp_rules",
		secondDirName: "banp_test_core_ingress_tcp_swapping_rules",
		formats:       ValidDiffFormats,
	},
	{
		// description:
		// in banp default swapped allow rules from first dir with deny rules in second dir;
		// so results should be changed as rules order must be respected
		firstDirName:  "banp_test_core_ingress_udp_rules",
		secondDirName: "banp_test_core_ingress_udp_swapping_rules",
		formats:       ValidDiffFormats,
	},
	{
		// description:
		// With user-defined networks, the need for complex network policies
		// are eliminated because isolation can be achieved by grouping workloads in different networks.
		// in first dir we have only pods (no policies, nether UDNs); each pod in a different namespace;
		// and by default all-conns are allowed between pods from the different namespaces.
		// in second dir we have same pods, but defined their namespaces with primary-user-defined-networks,
		// so the different namespaces are isolated; and the conns between pods from different
		// namespaces are blocked (no policies in the resources)
		firstDirName:  "only_pods_test",
		secondDirName: "udn_test_1",
		formats:       ValidDiffFormats,
	},
}

var commonBadPathTestsFatalErr = []struct {
	name             string
	ref1             string
	ref2             string
	errorStrContains string
}{
	{
		name:             "first_input_dir_has_netpol_with_invalid_cidr_should_return_fatal_error_of_invalid_CIDR_address",
		ref1:             filepath.Join("bad_netpols", "subdir1"),
		ref2:             "ipblockstest",
		errorStrContains: alerts.CidrErrTitle,
	},
	{
		name:             "second_input_dir_has_netpol_with_bad_label_key_should_return_fatal_selector_error",
		ref1:             "ipblockstest",
		ref2:             filepath.Join("bad_netpols", "subdir2"),
		errorStrContains: alerts.SelectorErrTitle,
	},
	{
		name:             "first_input_dir_has_netpol_with_invalid_rule_peer_should_return_fatal_rule_NetworkPolicyPeer_error",
		ref1:             filepath.Join("bad_netpols", "subdir3"),
		ref2:             "ipblockstest",
		errorStrContains: netpolerrors.ConcatErrors(alerts.RulePeerErrTitle, alerts.CombinedRulePeerErrStr),
	},
	{
		name:             "second_input_dir_has_netpol_with_empty_rule_peer_should_return_fatal_rule_NetworkPolicyPeer_error",
		ref1:             "ipblockstest",
		ref2:             filepath.Join("bad_netpols", "subdir4"),
		errorStrContains: netpolerrors.ConcatErrors(alerts.RulePeerErrTitle, alerts.EmptyRulePeerErrStr),
	},
	{
		name:             "second_input_dir_has_netpol_with_named_port_on_ipblock_peer_should_return_fatal_named_port_error",
		ref1:             "ipblockstest",
		ref2:             filepath.Join("bad_netpols", "subdir6"),
		errorStrContains: netpolerrors.ConcatErrors(alerts.NamedPortErrTitle, alerts.ConvertNamedPortErrStr),
	},
	/*{
		name:             "first_input_dir_does_not_exist_should_return_fatal_error_dir_not_found",
		dir1:             filepath.Join("bad_yamls", "subdir3"),
		dir2:             "ipblockstest",
		errorStrContains: "was not found",
	},*/
	{
		name:             "first_input_dir_has_illegal_podlist_pods_with_same_owner_ref_name_has_different_labels_should_return_fatal_error",
		ref1:             "semanticDiff-same-topologies-illegal-podlist",
		ref2:             "semanticDiff-same-topologies-old1",
		errorStrContains: alerts.NotSupportedPodResourcesErrorStr("demo/cog-agents"),
	},
	{
		name:             "first_input_dir_has_two_admin_netpols_with_same_priority_should_return_fatal_error",
		ref1:             "anp_bad_path_test_1",
		ref2:             "anp_test_4",
		errorStrContains: alerts.PriorityErrExplain,
	},
	{
		name:             "second_input_dir_has_an_admin_netpol_with_invalid_priority_should_return_fatal_error",
		ref1:             "anp_test_4",
		ref2:             "anp_bad_path_test_2",
		errorStrContains: alerts.PriorityValueErr("invalid-priority", 1001),
	},
	{
		name:             "first_input_dir_has_two_admin_netpols_with_same_name_should_return_fatal_error",
		ref1:             "anp_bad_path_test_3",
		ref2:             "anp_test_4",
		errorStrContains: alerts.ANPsWithSameNameErr("same-name"),
	},
	{
		name:             "first_input_dir_has_two_netpols_with_same_name_in_one_namespace_should_return_fatal_error",
		ref1:             "np_bad_path_test_1",
		ref2:             "ipblockstest",
		errorStrContains: alerts.NPWithSameNameError("default/backend-netpol"),
	},
	{
		name:             "first_input_dir_has_an_admin_netpol_with_empty_subject_should_return_fatal_error",
		ref1:             "anp_bad_path_test_4",
		ref2:             "anp_test_4",
		errorStrContains: alerts.OneFieldSetSubjectErr,
	},
	{
		name:             "second_input_dir_has_an_admin_netpol_with_an_invalid_egress_rule_peer_should_return_fatal_error",
		ref1:             "anp_test_4",
		ref2:             "anp_bad_path_test_7",
		errorStrContains: alerts.OneFieldSetRulePeerErr,
	},
	{
		name:             "first_input_dir_has_an_admin_netpol_missing_ingress_rule_peer_should_return_fatal_error",
		ref1:             "anp_bad_path_test_14",
		ref2:             "anp_test_4",
		errorStrContains: alerts.ANPIngressRulePeersErr,
	},
	{
		name:             "first_input_dir_has_an_admin_netpol_with_an_invalid_ingress_rule_port_should_return_fatal_error",
		ref1:             "anp_bad_path_test_17",
		ref2:             "anp_test_4",
		errorStrContains: alerts.ANPPortsError,
	},
	{
		name:             "second_input_dir_has_baseline_admin_netpol_with_an_invalid_egress_rule_action_should_return_fatal_error",
		ref1:             "banp_test_core_egress_sctp_rules",
		ref2:             "banp_bad_path_test_8",
		errorStrContains: alerts.UnknownRuleActionErr,
	},
	{
		name:             "first_input_dir_has_baseline_admin_netpol_with_an_invalid_ingress_rule_peer_should_return_fatal_error",
		ref1:             "banp_bad_path_test_12",
		ref2:             "banp_test_core_egress_sctp_rules",
		errorStrContains: alerts.OneFieldSetRulePeerErr,
	},
	{
		name:             "second_input_dir_has_baseline_admin_netpol_with_an_invalid_egress_cidr_peer_should_return_fatal_error",
		ref1:             "banp_test_core_egress_sctp_rules",
		ref2:             "banp_bad_path_test_15",
		errorStrContains: alerts.InvalidCIDRAddr,
	},
}
