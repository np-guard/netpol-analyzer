package diff

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/netpol-analyzer/pkg/internal/output"
	"github.com/np-guard/netpol-analyzer/pkg/internal/testutils"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/fsscanner"
)

var allFormats = []string{output.TextFormat, output.MDFormat, output.CSVFormat, output.DOTFormat}

const ResourceInfosFunc = "ConnDiffFromResourceInfos"
const DirPathFunc = "ConnDiffFromDirPaths"
const currentPkg = "diff"

var diffTestedAPIS = []string{ResourceInfosFunc, DirPathFunc}

//////////////////////////////////good path tests/////////////////////////////////////////////////////////////////////////

// TestDiff tests the output for valid input resources, for both apis (ConnDiffFromResourceInfos , ConnDiffFromDirPaths)
func TestDiff(t *testing.T) {
	t.Parallel()
	for _, tt := range goodPathTests {
		tt := tt
		testName := testutils.DiffTestName(tt.firstDirName, tt.secondDirName)
		t.Run(testName, func(t *testing.T) {
			t.Parallel()
			for _, format := range tt.formats {
				for _, apiFunc := range diffTestedAPIS {
					pTest, diffRes, err := getAnalysisResFromAPI(apiFunc, tt.firstDirName, tt.secondDirName, format, "")
					require.Nil(t, err, pTest.testInfo)
					actualOutput, err := pTest.analyzer.ConnectivityDiffToString(diffRes)
					require.Nil(t, err, pTest.testInfo)
					testutils.CheckActualVsExpectedOutputMatch(t, pTest.expectedOutputFileName, actualOutput,
						pTest.testInfo, "", currentPkg, testutils.StandardPkgLevelDepth)
				}
			}
		})
	}
}

/////////////////////////////////////bad path tests /////////////////////////////////////////////////////////////////////////////////

// fatal errors common for both interfaces (ConnDiffFromDirPaths & ConnDiffFromResourceInfos)
//--------------------------------------------------------------------------------------------

// TestDiffAnalyzeFatalErrors tests fatal errors returned while computing the connectivity diff
func TestDiffAnalyzeFatalErrors(t *testing.T) {
	t.Parallel()
	for _, tt := range commonBadPathTestsFatalErr {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			for _, apiFunc := range diffTestedAPIS {
				pTest, diffRes, err := getAnalysisResFromAPI(apiFunc, tt.ref1, tt.ref2, output.DefaultFormat, tt.name)
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
				"unable to decode", // "at dir 1" currently printed to log, but not attached to err itself
				"at ref1: no relevant Kubernetes workload resources found",
				"at ref1: no relevant Kubernetes network policy resources found",
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
				"at ref1: no relevant Kubernetes workload resources found",
				"at ref1: no relevant Kubernetes network policy resources found",
			},
			emptyRes: false, // expecting diff result because ref2 has resources
		},
		{
			name: "first_input_dir_has_no_netpols_should_get_no_relevant_k8s_policies_found",
			ref1: "k8s_ingress_test",
			ref2: "k8s_ingress_test_new",
			containedErrOrWarns: []string{
				"at ref1: no relevant Kubernetes network policy resources found",
			},
			emptyRes: false, // expecting diff result, both dirs have resources
		},
		{
			name: "in_second_input_dir_network_policies_block_ingress_conns_to_a_workload_should_get_warning_msg",
			ref1: "acs-security-demos",
			ref2: "acs-security-demos-new",
			containedErrOrWarns: []string{
				"at ref2: Route resource frontend/asset-cache specified workload frontend/asset-cache[Deployment] as a backend",
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
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			for _, apiFunc := range diffTestedAPIS {
				if tt.onlyDirPathsAPI && apiFunc != DirPathFunc {
					continue
				}

				pTest, diffRes, err := getAnalysisResFromAPI(apiFunc, tt.ref1, tt.ref2, output.DefaultFormat, tt.name)
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
				"[the path ", "some_dir", "does not exist", "some_other_dir",
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
				"[the path ", "some_dir", "does not exist", "unable to decode", "connlist_output.json",
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
				"unable to decode", "connlist_output.json", "error reading file",
			},
			emptyRes: false, // no diff, but ConnectivityDiff contains non-changed conns
			isFatal:  false,
		},
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pTest, diffRes, err := getAnalysisResFromAPI(DirPathFunc, tt.ref1, tt.ref2, output.DefaultFormat, tt.name)
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
			errorStrContains: "png output format is not supported.",
		},
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			for _, apiFunc := range diffTestedAPIS {
				pTest, connsDiff, err := getAnalysisResFromAPI(apiFunc, tt.ref1, tt.ref2, tt.format, tt.name)
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
		analyzer := NewDiffAnalyzer(WithOutputFormat(format), WithArgNames("old", "new"))
		diffRes, err := analyzer.ConnDiffFromDirPaths(filepath.Join(testutils.GetTestsDir(), ref1),
			filepath.Join(testutils.GetTestsDir(), ref2))
		require.Nil(t, err)
		require.NotEmpty(t, diffRes)
		res, err := analyzer.ConnectivityDiffToString(diffRes)
		require.Nil(t, err)
		testName := "TsetOutputWithArgNamesOption_" + testutils.DiffTestName(ref1, ref2) + testutils.DotSign + format
		testutils.CheckActualVsExpectedOutputMatch(t, testName, res, testName, "", currentPkg,
			testutils.StandardPkgLevelDepth)
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
	var testName string
	if testNameStr != "" {
		testName = testNameStr
	} else {
		testName = testutils.DiffTestName(firstDir, secondDir)
	}

	return &preparedTest{
		testName:               testName,
		expectedOutputFileName: testName + testutils.DotSign + format,
		testInfo:               fmt.Sprintf("test: %q, output format: %q, api func: %q", testName, format, apiName),
		analyzer:               NewDiffAnalyzer(WithOutputFormat(format)),
		firstDirPath:           filepath.Join(testutils.GetTestsDir(), firstDir),
		secondDirPath:          filepath.Join(testutils.GetTestsDir(), secondDir),
	}
}

func getAnalysisResFromAPI(apiName, firstDir, secondDir, format, testName string) (
	pTest *preparedTest, diffRes ConnectivityDiff, err error) {
	pTest = prepareTest(firstDir, secondDir, format, apiName, testName)
	switch apiName {
	case ResourceInfosFunc:
		infos1, _ := fsscanner.GetResourceInfosFromDirPath([]string{pTest.firstDirPath}, true, false)
		infos2, _ := fsscanner.GetResourceInfosFromDirPath([]string{pTest.secondDirPath}, true, false)
		diffRes, err = pTest.analyzer.ConnDiffFromResourceInfos(infos1, infos2)
	case DirPathFunc:
		diffRes, err = pTest.analyzer.ConnDiffFromDirPaths(pTest.firstDirPath, pTest.secondDirPath)
	}
	return pTest, diffRes, err
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
		formats:       allFormats,
	},
	{
		// description:
		// **changed netpols: default/frontend-netpol, default/adservice-netpol, default/checkoutservice-netpol,
		// 		default/cartservice-netpol, default/currencyservice-netpol, default/emailservice-netpol
		// **added netpols : default/redis-cart-netpol
		// **added workloads: default/unicorn
		firstDirName:  "onlineboutique_workloads",
		secondDirName: "onlineboutique_workloads_changed_netpols_and_workloads",
		formats:       allFormats,
	},
	{
		// description:
		// **added workloads: default/unicorn
		firstDirName:  "onlineboutique_workloads",
		secondDirName: "onlineboutique_workloads_changed_workloads",
		formats:       allFormats,
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
		formats:       allFormats,
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
		formats:       allFormats,
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
		formats:       allFormats,
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
		formats:       allFormats,
	},
	{
		// description:
		// **changed netpols : default/backend-netpol,
		firstDirName:  "netpol-analysis-example-minimal",
		secondDirName: "netpol-diff-example-minimal",
		formats:       allFormats,
	},
	{
		// description:
		// **removed netpol: enable-all-protocols-with-all-ports
		// **added netpol: enable-all-traffic
		firstDirName:  "with_end_port_example",
		secondDirName: "with_end_port_example_new",
		formats:       allFormats,
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
		errorStrContains: "network policy default/shippingservice-netpol CIDR error: invalid CIDR address: A",
	},
	{
		name: "second_input_dir_has_netpol_with_bad_label_key_should_return_fatal_selector_error",
		ref1: "ipblockstest",
		ref2: filepath.Join("bad_netpols", "subdir2"),
		errorStrContains: "network policy default/shippingservice-netpol selector error: key: Invalid value: \"app@b\": " +
			"name part must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric" +
			" character (e.g. 'MyName',  or 'my.name',  or '123-abc', regex used for validation is '([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]')",
	},
	{
		name: "first_input_dir_has_netpol_with_invalid_rule_peer_should_return_fatal_rule_NetworkPolicyPeer_error",
		ref1: filepath.Join("bad_netpols", "subdir3"),
		ref2: "ipblockstest",
		errorStrContains: "network policy default/shippingservice-netpol rule NetworkPolicyPeer error: " +
			"cannot have both IPBlock and PodSelector/NamespaceSelector set",
	},
	{
		name:             "second_input_dir_has_netpol_with_empty_rule_peer_should_return_fatal_rule_NetworkPolicyPeer_error",
		ref1:             "ipblockstest",
		ref2:             filepath.Join("bad_netpols", "subdir4"),
		errorStrContains: "network policy default/shippingservice-netpol rule NetworkPolicyPeer error: cannot have empty rule peer",
	},
	{
		name:             "second_input_dir_has_netpol_with_named_port_on_ipblock_peer_should_return_fatal_named_port_error",
		ref1:             "ipblockstest",
		ref2:             filepath.Join("bad_netpols", "subdir6"),
		errorStrContains: "network policy default/shippingservice-netpol named port error: cannot convert named port for an IP destination",
	},
	/*{
		name:             "first_input_dir_does_not_exist_should_return_fatal_error_dir_not_found",
		dir1:             filepath.Join("bad_yamls", "subdir3"),
		dir2:             "ipblockstest",
		errorStrContains: "was not found",
	},*/
	{
		name: "first_input_dir_has_illegal_podlist_pods_with_same_owner_ref_name_has_different_labels_should_return_fatal_error",
		ref1: "semanticDiff-same-topologies-illegal-podlist",
		ref2: "semanticDiff-same-topologies-old1",
		errorStrContains: "Input Pod resources are not supported for connectivity analysis." +
			" Found Pods of the same owner demo/cog-agents but with different set of labels.",
	},
}
