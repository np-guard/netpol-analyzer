package diff

/*
import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/common"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/testutils"
)

const expectedOutputFilePrefix = "diff_output_from_"

var allFormats = []string{common.TextFormat, common.MDFormat, common.CSVFormat, common.DOTFormat}

// helping func constructs diffAnalyzer with required options and computes the connectivity diff from the dir paths
func constructAnalyzerAndGetDiffFromDirPaths(opts []DiffAnalyzerOption, dir1, dir2 string) (*DiffAnalyzer, ConnectivityDiff, error) {
	diffAnalyzer := NewDiffAnalyzer(opts...)

	firstDirPath := filepath.Join(testutils.GetTestsDir(), dir1)
	secondDirPath := filepath.Join(testutils.GetTestsDir(), dir2)
	connsDiff, err := diffAnalyzer.ConnDiffFromDirPaths(firstDirPath, secondDirPath)

	return diffAnalyzer, connsDiff, err
}

// TestDiff tests the output of ConnDiffFromDirPaths() for valid input resources
func TestDiff(t *testing.T) {
	t.Parallel()
	cases := []struct {
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
			formats:       []string{common.CSVFormat},
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
			formats:       []string{common.DefaultFormat},
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
			formats:       []string{common.DefaultFormat},
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
			formats:       []string{common.DefaultFormat},
		},
		{
			// description:
			// **changed netpols: demo/ui-to-command, demo/query-to-ui
			firstDirName:  "multiple_topology_resources_1",
			secondDirName: "multiple_topology_resources_2",
			formats:       []string{common.DefaultFormat},
		},
		{
			// description:
			// **added netpol: default/policy-from2-to1
			firstDirName:  "multiple_topology_resources_3",
			secondDirName: "multiple_topology_resources_4",
			formats:       []string{common.DefaultFormat},
		},
		{
			// description:
			// **changed netpols: limited egress in all policies , and limited ingress for loadgenerator
			firstDirName:  "new_online_boutique",
			secondDirName: "new_online_boutique_synthesis",
			formats:       []string{common.DefaultFormat},
		},
		{
			// description:
			// **changed netpols: demo/ui-to-command, demo/query-to-ui
			firstDirName:  "semanticDiff-same-topologies-old1",
			secondDirName: "semanticDiff-same-topologies-new1",
			formats:       []string{common.DefaultFormat},
		},
		{
			// description:
			// **changed netpols: demo/ui-to-command, demo/query-to-ui
			firstDirName:  "semanticDiff-same-topologies-old1",
			secondDirName: "semanticDiff-same-topologies-new1a",
			formats:       []string{common.DefaultFormat},
		},
		{
			// description:
			// **changed netpols: demo/ui-to-command
			firstDirName:  "semanticDiff-same-topologies-old2",
			secondDirName: "semanticDiff-same-topologies-new2",
			formats:       []string{common.DefaultFormat},
		},
		{
			// description:
			// **changed netpols: demo/query-to-ui
			// **removed netpols: demo/capture-ui
			// **added netpols: demo/capture-query
			firstDirName:  "semanticDiff-same-topologies-old3",
			secondDirName: "semanticDiff-same-topologies-new3",
			formats:       []string{common.DefaultFormat},
		},
		{
			// description:
			// **added netpols: default/policy-from2-to1
			firstDirName:  "semanticDiff-orig-topologies-no-policy",
			secondDirName: "semanticDiff-orig-topologies-policy-a",
			formats:       []string{common.DefaultFormat},
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
			formats:       []string{common.DefaultFormat},
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
			formats:       []string{common.DefaultFormat},
		},
		{
			// description:
			// **different topologies
			// **different policies
			firstDirName:  "semanticDiff-same-topologies-old1",
			secondDirName: "semanticDiff-different-topologies-policy-a",
			formats:       []string{common.DefaultFormat},
		},
		{
			// description:
			// **changed netpols: kube-system/enable-from-ipblock-to-isolated-by-tier
			firstDirName:  "ipblockstest",
			secondDirName: "ipblockstest_2",
			formats:       []string{common.DefaultFormat},
		},
		{
			// description:
			// **changed netpols: kube-system/enable-from-ipblock-to-isolated-by-tier
			firstDirName:  "ipblockstest",
			secondDirName: "ipblockstest_3",
			formats:       []string{common.DefaultFormat},
		},
		{
			// description:
			// **changed netpols: kube-system/enable-from-ipblock-to-isolated-by-tier
			firstDirName:  "ipblockstest_2",
			secondDirName: "ipblockstest_3",
			formats:       []string{common.DefaultFormat},
		},
		{
			// description:
			// **changed netpols: kube-system/enable-from-ipblock-to-isolated-by-tier
			firstDirName:  "ipblockstest",
			secondDirName: "ipblockstest_4",
			formats:       []string{common.DefaultFormat},
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
			formats:       []string{common.DefaultFormat},
		},
		{
			// description:
			// **removed netpol: kube-system/ingress-based-on-named-ports
			// **added netpol: kube-system/ingress-based-on-port-number
			firstDirName:  "test_with_named_ports_changed_netpol_2",
			secondDirName: "test_with_named_ports_changed_netpol_3",
			formats:       []string{common.DefaultFormat},
		},
	}
	for _, tt := range cases {
		tt := tt
		testName := "diff_between_" + tt.secondDirName + "_and_" + tt.firstDirName
		t.Run(testName, func(t *testing.T) {
			t.Parallel()
			for _, format := range tt.formats {
				expectedOutputFileName := expectedOutputFilePrefix + tt.firstDirName + "." + format
				analyzerOpts := []DiffAnalyzerOption{WithOutputFormat(format), WithIncludeJSONManifests()}
				diffAnalyzer, connsDiff, err := constructAnalyzerAndGetDiffFromDirPaths(analyzerOpts, tt.firstDirName, tt.secondDirName)
				require.Nil(t, err, testutils.GetDebugMsgWithTestNameAndFormat(testName, format))
				actualOutput, err := diffAnalyzer.ConnectivityDiffToString(connsDiff)
				require.Nil(t, err, testutils.GetDebugMsgWithTestNameAndFormat(testName, format))
				testutils.CheckActualVsExpectedOutputMatch(t, testName, tt.secondDirName, expectedOutputFileName, actualOutput, format)
			}
		})
	}
}

// TestDiffAnalyzeFatalErrors tests fatal errors returned while computing the connectivity diff
func TestDiffAnalyzeFatalErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name             string
		dir1             string
		dir2             string
		errorStrContains string
	}{
		{
			name:             "first_input_dir_has_netpol_with_invalid_cidr_should_return_fatal_error_of_invalid_CIDR_address",
			dir1:             filepath.Join("bad_netpols", "subdir1"),
			dir2:             "ipblockstest",
			errorStrContains: "network policy default/shippingservice-netpol CIDR error: invalid CIDR address: A",
		},
		{
			name: "second_input_dir_has_netpol_with_bad_label_key_should_return_fatal_selector_error",
			dir1: "ipblockstest",
			dir2: filepath.Join("bad_netpols", "subdir2"),
			errorStrContains: "network policy default/shippingservice-netpol selector error: key: Invalid value: \"app@b\": " +
				"name part must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric" +
				" character (e.g. 'MyName',  or 'my.name',  or '123-abc', regex used for validation is '([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]')",
		},
		{
			name: "first_input_dir_has_netpol_with_invalid_rule_peer_should_return_fatal_rule_NetworkPolicyPeer_error",
			dir1: filepath.Join("bad_netpols", "subdir3"),
			dir2: "ipblockstest",
			errorStrContains: "network policy default/shippingservice-netpol rule NetworkPolicyPeer error: " +
				"cannot have both IPBlock and PodSelector/NamespaceSelector set",
		},
		{
			name:             "second_input_dir_has_netpol_with_empty_rule_peer_should_return_fatal_rule_NetworkPolicyPeer_error",
			dir1:             "ipblockstest",
			dir2:             filepath.Join("bad_netpols", "subdir4"),
			errorStrContains: "network policy default/shippingservice-netpol rule NetworkPolicyPeer error: cannot have empty rule peer",
		},
		{
			name:             "second_input_dir_has_netpol_with_named_port_on_ipblock_peer_should_return_fatal_named_port_error",
			dir1:             "ipblockstest",
			dir2:             filepath.Join("bad_netpols", "subdir6"),
			errorStrContains: "network policy default/shippingservice-netpol named port error: cannot convert named port for an IP destination",
		},
		{
			name:             "first_input_dir_does_not_exist_should_return_fatal_error_dir_not_found",
			dir1:             filepath.Join("bad_yamls", "subdir3"),
			dir2:             "ipblockstest",
			errorStrContains: "was not found",
		},
		{
			name: "first_input_dir_has_illegal_podlist_pods_with_same_owner_ref_name_has_different_labels_should_return_fatal_error",
			dir1: "semanticDiff-same-topologies-illegal-podlist",
			dir2: "semanticDiff-same-topologies-old1",
			errorStrContains: "Input Pod resources are not supported for connectivity analysis." +
				" Found Pods of the same owner demo/cog-agents but with different set of labels.",
		},
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			analyzerOpts := []DiffAnalyzerOption{WithIncludeJSONManifests()}
			_, connsDiff, err := constructAnalyzerAndGetDiffFromDirPaths(analyzerOpts, tt.dir1, tt.dir2)
			require.Empty(t, connsDiff, "test: %q", tt.name)
			testutils.CheckErrorContainment(t, tt.name, tt.errorStrContains, err.Error(), true)
		})
	}
}

// TestDiffOutputFatalErrors tests fatal errors returned while writing the diff to string in given output format
func TestDiffOutputFatalErrors(t *testing.T) {
	t.Parallel()
	formattingErrType := &resultFormattingError{} // error returned from getting/writing output format
	cases := []struct {
		name             string
		dir1             string
		dir2             string
		format           string
		errorStrContains string
	}{
		{
			name:             "giving_unsupported_output_format_option_should_return_fatal_error",
			dir1:             "onlineboutique_workloads",
			dir2:             "onlineboutique_workloads_changed_netpols",
			format:           "png",
			errorStrContains: "png output format is not supported.",
		},
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			analyzerOpts := []DiffAnalyzerOption{WithOutputFormat(tt.format)}
			analyzer, connsDiff, err := constructAnalyzerAndGetDiffFromDirPaths(analyzerOpts, tt.dir1, tt.dir2)
			require.Nil(t, err, "test: %q", tt.name)
			output, err := analyzer.ConnectivityDiffToString(connsDiff)
			require.Empty(t, output, "test: %q", tt.name)
			testutils.CheckErrorContainment(t, tt.name, tt.errorStrContains, err.Error(), true)
			// check error type
			diffErrors := analyzer.Errors()
			require.True(t, errors.As(diffErrors[0].Error(), &formattingErrType), "test: %q, mismatch in error type, should get %v",
				tt.name, &formattingErrType)
		})
	}
}

// TestDiffAnalyzerSevereErrors tests diff analyzer behavior with severe error, analyzer without stopOnError
// will continue running regularly, analyzer with stopOnError will stop on first severe error and return empty result
func TestDiffAnalyzerSevereErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name                           string
		dir1                           string
		dir2                           string
		firstErrStrContains            string
		expectedErrNumWithoutStopOnErr int
		expectedErrNumWithStopOnErr    int
	}{
		{
			// description: only first dir has severe error ,
			// it also has a warning which was captured before the severe error so expected to appear in both
			name:                           "first_input_dir_has_no_k8s_resources_should_return_severe_error",
			dir1:                           filepath.Join("bad_yamls", "not_a_k8s_resource.yaml"),
			dir2:                           "ipblockstest", // no warnings, nor any severe/fatal errors
			firstErrStrContains:            "Yaml document is not a K8s resource",
			expectedErrNumWithoutStopOnErr: 2,
			expectedErrNumWithStopOnErr:    2,
		},
		{
			// description: only first dir has severe error , it also has a warning
			// the severe error is captured first, so we expect not to see the warning when running with stopOnError as it stops running
			name:                           "input_file_in_first_dir_has_malformed_yaml_doc_should_return_severe_error",
			dir1:                           filepath.Join("bad_yamls", "document_with_syntax_error.yaml"),
			dir2:                           "ipblockstest", // no warnings, nor any severe/fatal errors
			firstErrStrContains:            "YAML document is malformed",
			expectedErrNumWithoutStopOnErr: 2,
			expectedErrNumWithStopOnErr:    1,
		},
		{
			// dirty directory, includes 3 severe errors
			// when running without stopOnError we expect to see 6 severe errors (3 for each dir flag)
			// but when running with stopOnError we expect to see only 1 , and then stops
			name:                           "both_input_dirs_contain_malformed_yaml_files_should_return_severe_errors",
			dir1:                           "dirty",
			dir2:                           "dirty",
			firstErrStrContains:            "YAML document is malformed",
			expectedErrNumWithoutStopOnErr: 6,
			expectedErrNumWithStopOnErr:    1,
		},
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			analyzerOpts1 := []DiffAnalyzerOption{}
			analyzerOpts2 := []DiffAnalyzerOption{WithStopOnError()}
			// severe is not fatal, thus not returned
			// first analyzer:
			analyzer, _, err1 := constructAnalyzerAndGetDiffFromDirPaths(analyzerOpts1, tt.dir1, tt.dir2)
			diffErrors1 := analyzer.Errors()
			require.Nil(t, err1, "test: %q", tt.name)
			require.Equal(t, tt.expectedErrNumWithoutStopOnErr, len(diffErrors1),
				"test: %q, mismatch in number of errors, expected %d, got %d", tt.name, tt.expectedErrNumWithoutStopOnErr, len(diffErrors1))
			testutils.CheckErrorContainment(t, tt.name, tt.firstErrStrContains, diffErrors1[0].Error().Error(), true)
			// second analyzer (with stopOnError):
			analyzerWithStopOnError, res, err2 := constructAnalyzerAndGetDiffFromDirPaths(analyzerOpts2, tt.dir1, tt.dir2)
			diffErrors2 := analyzerWithStopOnError.Errors()
			require.Nil(t, err2, "test: %q", tt.name)
			require.Empty(t, res, "test: %q", tt.name) // the run stopped on first severe error, no result computed
			require.Equal(t, tt.expectedErrNumWithStopOnErr, len(diffErrors2),
				"test: %q, mismatch in number of errors, expected %d, got %d", tt.name, tt.expectedErrNumWithStopOnErr, len(diffErrors2))
			testutils.CheckErrorContainment(t, tt.name, tt.firstErrStrContains, diffErrors2[0].Error().Error(), true)
		})
	}
}

// TestDiffAnalyzerWarnings tests diff analyzer behavior when there are warning messages - expected to run regularly
func TestDiffAnalyzerWarnings(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name                string
		dir1                string
		dir2                string
		firstErrStrContains string
	}{
		{
			name:                "first_input_dir_with_no_yamls_should_get_warnings_no_yamls_and_no_k8s_resources",
			dir1:                filepath.Join("bad_yamls", "subdir2"),
			dir2:                "ipblockstest",
			firstErrStrContains: "no yaml files found",
		},
		{
			name:                "first_input_dir_has_no_netpols_should_get_no_relevant_k8s_policies_found",
			dir1:                "k8s_ingress_test",
			dir2:                "k8s_ingress_test_new",
			firstErrStrContains: "no relevant Kubernetes network policy resources found",
		},
		{
			name: "in_second_input_dir_network_policies_block_ingress_conns_to_a_workload_should_get_warning_msg",
			dir1: "acs-security-demos",
			dir2: "acs-security-demos-new",
			firstErrStrContains: "Route resource frontend/asset-cache specified workload frontend/asset-cache[Deployment] as a backend," +
				" but network policies are blocking ingress connections from an arbitrary in-cluster source to this workload.",
		},
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			analyzerOpts := []DiffAnalyzerOption{}
			analyzer, connsDiff, err := constructAnalyzerAndGetDiffFromDirPaths(analyzerOpts, tt.dir1, tt.dir2)
			require.NotNil(t, connsDiff, "test: %q", tt.name)
			require.Nil(t, err, "test: %q", tt.name)
			diffErrs := analyzer.Errors()
			require.GreaterOrEqual(t, len(diffErrs), 1, "test: %q", tt.name) // at least 1 warning
			testutils.CheckErrorContainment(t, tt.name, tt.firstErrStrContains, diffErrs[0].Error().Error(), false)
		})
	}
}
*/
