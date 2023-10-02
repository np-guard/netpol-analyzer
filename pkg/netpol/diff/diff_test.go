package diff

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/common"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/testutils"
)

type testEntry struct {
	firstDirName  string
	secondDirName string
	formats       []string
}

const expectedOutputFilePrefix = "diff_output_from_"

var allFormats = []string{common.TextFormat, common.MDFormat, common.CSVFormat, common.DOTFormat}

func TestDiff(t *testing.T) {
	testingEntries := []testEntry{
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

	for _, entry := range testingEntries {
		firstDirPath := filepath.Join(testutils.GetTestsDir(), entry.firstDirName)
		secondDirPath := filepath.Join(testutils.GetTestsDir(), entry.secondDirName)
		for _, format := range entry.formats {
			expectedOutputFileName := expectedOutputFilePrefix + entry.firstDirName + "." + format
			expectedOutputFilePath := filepath.Join(secondDirPath, expectedOutputFileName)

			diffAnalyzer := NewDiffAnalyzer(WithOutputFormat(format), WithIncludeJSONManifests())
			connsDiff, err := diffAnalyzer.ConnDiffFromDirPaths(firstDirPath, secondDirPath)
			require.Empty(t, err)
			actualOutput, err := diffAnalyzer.ConnectivityDiffToString(connsDiff)
			require.Empty(t, err)
			expectedOutputStr, err := os.ReadFile(expectedOutputFilePath)
			require.Empty(t, err)
			require.Equal(t, string(expectedOutputStr), actualOutput)
		}
	}
}

type testErrEntry struct {
	name                           string
	dir1                           string
	dir2                           string
	firstErrStr                    string
	isFormattingErr                bool
	format                         string
	expectedErrNumWithoutStopOnErr int
	expectedErrNumWithStopOnErr    int
}

var formattingErrType = &resultFormattingError{} // error returned from getting/writing output format

// constructs diffAnalyzer with required options and computes the connectivity diff from the dir paths
func constructAnalyzerAndGetDiffFromDirPaths(stopOnErr bool, format, dir1, dir2 string) (*DiffAnalyzer, ConnectivityDiff, error) {
	diffAnalyzerOptions := []DiffAnalyzerOption{WithIncludeJSONManifests()}
	if format != "" {
		diffAnalyzerOptions = append(diffAnalyzerOptions, WithOutputFormat(format))
	}
	if stopOnErr {
		diffAnalyzerOptions = append(diffAnalyzerOptions, WithStopOnError())
	}

	diffAnalyzer := NewDiffAnalyzer(diffAnalyzerOptions...)

	firstDirPath := filepath.Join(testutils.GetTestsDir(), dir1)
	secondDirPath := filepath.Join(testutils.GetTestsDir(), dir2)
	connsDiff, err := diffAnalyzer.ConnDiffFromDirPaths(firstDirPath, secondDirPath)

	return diffAnalyzer, connsDiff, err
}

// following testing funcs will run on two diff analyzers , one analyzer runs with stopOnFirstError flag, the other without it.

func TestFatalErrors(t *testing.T) {
	// testing behavior with fatal errors, it always should stop running for both analyzers
	cases := []testErrEntry{
		{
			name:            "unsupported format",
			dir1:            "onlineboutique_workloads",
			dir2:            "onlineboutique_workloads_changed_netpols",
			format:          "png",
			firstErrStr:     "png output format is not supported.",
			isFormattingErr: true,
		},
		{
			name:        "dir 1 with bad netpol - CIDR error",
			dir1:        filepath.Join("bad_netpols", "subdir1"),
			dir2:        "ipblockstest",
			firstErrStr: "network policy default/shippingservice-netpol CIDR error: invalid CIDR address: A",
		},
		{
			name: "dir 2 with bad netpol - label key error",
			dir1: "ipblockstest",
			dir2: filepath.Join("bad_netpols", "subdir2"),
			firstErrStr: "network policy default/shippingservice-netpol selector error: key: Invalid value: \"app@b\": " +
				"name part must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric" +
				" character (e.g. 'MyName',  or 'my.name',  or '123-abc', regex used for validation is '([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]')",
		},
		{
			name: "dir 1 with bad netpol - bad rule",
			dir1: filepath.Join("bad_netpols", "subdir3"),
			dir2: "ipblockstest",
			firstErrStr: "network policy default/shippingservice-netpol rule NetworkPolicyPeer error: " +
				"cannot have both IPBlock and PodSelector/NamespaceSelector set",
		},
		{
			name:        "dir 2 with bad netpol - empty rule",
			dir1:        "ipblockstest",
			dir2:        filepath.Join("bad_netpols", "subdir4"),
			firstErrStr: "network policy default/shippingservice-netpol rule NetworkPolicyPeer error: cannot have empty rule peer",
		},
		{
			name:        "dir 2 with bad netpol - named port on ipblock error",
			dir1:        "ipblockstest",
			dir2:        filepath.Join("bad_netpols", "subdir6"),
			firstErrStr: "network policy default/shippingservice-netpol named port error: cannot convert named port for an IP destination",
		},
		{
			name:        "dir 1 does not exists",
			dir1:        filepath.Join("bad_yamls", "subdir3"),
			dir2:        "ipblockstest",
			firstErrStr: "error accessing directory:",
		},
		{
			name: "dir 1 includes illegal pods list",
			dir1: "semanticDiff-same-topologies-illegal-podlist",
			dir2: "semanticDiff-same-topologies-old1",
			firstErrStr: "Resources not supported for connectivity analysis. Pods with the ownerReferences' Name: cog-agents have different labels." +
				" Some labels' keys with different values: app",
		},
	}
	for _, entry := range cases {
		diffAnalyzer, connsDiff1, err1 := constructAnalyzerAndGetDiffFromDirPaths(false, entry.format, entry.dir1, entry.dir2)
		diffAnalyzerStopsOnError, connsDiff2, err2 := constructAnalyzerAndGetDiffFromDirPaths(true, entry.format, entry.dir1, entry.dir2)

		if !entry.isFormattingErr {
			require.Nil(t, connsDiff1, "test: %s", entry.name)
			require.Nil(t, connsDiff2, "test: %s", entry.name)
			require.Contains(t, err1.Error(), entry.firstErrStr, "test: %s", entry.name)
			require.Contains(t, err2.Error(), entry.firstErrStr, "test: %s", entry.name)
			continue
		}

		// else - formatting error , try to write result to string to get the fatal err
		_, err1 = diffAnalyzer.ConnectivityDiffToString(connsDiff1)
		_, err2 = diffAnalyzerStopsOnError.ConnectivityDiffToString(connsDiff2)
		diffErrors1 := diffAnalyzer.Errors()
		require.Equal(t, err1.Error(), entry.firstErrStr, "test: %s", entry.name)
		require.Equal(t, err2.Error(), entry.firstErrStr, "test: %s", entry.name)
		require.True(t, errors.As(diffErrors1[0].Error(), &formattingErrType), "test: %s", entry.name)
	}
}

func TestSevereErrors(t *testing.T) {
	// testing behavior with severe error, analyzer without stopOnError will continue running regularly,
	// analyzer with stopOnError will stop on first severe error and return empty result
	cases := []testErrEntry{
		{
			// description: only first dir has severe error ,
			// it also has a warning which was captured before the severe error so expected to appear in both
			name:                           "dir 1 has no k8s resources",
			dir1:                           filepath.Join("bad_yamls", "not_a_k8s_resource.yaml"),
			dir2:                           "ipblockstest", // no warnings, nor any severe/fatal errors
			firstErrStr:                    "Yaml document is not a K8s resource",
			expectedErrNumWithoutStopOnErr: 2,
			expectedErrNumWithStopOnErr:    2,
		},
		{
			// description: only first dir has severe error , it also has a warning
			// the severe error is captured first, so we expect not to see the warning when running with stopOnError as it stops running
			name:                           "dir 1 has malformed yaml",
			dir1:                           filepath.Join("bad_yamls", "document_with_syntax_error.yaml"),
			dir2:                           "ipblockstest", // no warnings, nor any severe/fatal errors
			firstErrStr:                    "YAML document is malformed",
			expectedErrNumWithoutStopOnErr: 2,
			expectedErrNumWithStopOnErr:    1,
		},
		{
			// dirty directory, includes 3 severe errors
			// when running without stopOnError we expect to see 6 severe errors (3 for each dir flag)
			// but when running with stopOnError we expect to see only 1 , and then stops
			name:                           "both dirs return severe errors on their malformed yaml files",
			dir1:                           "dirty",
			dir2:                           "dirty",
			firstErrStr:                    "YAML document is malformed",
			expectedErrNumWithoutStopOnErr: 6,
			expectedErrNumWithStopOnErr:    1,
		},
	}
	for _, entry := range cases {
		diffAnalyzer, _, err1 := constructAnalyzerAndGetDiffFromDirPaths(false, entry.format, entry.dir1, entry.dir2)
		require.Nil(t, err1, "test: %s", entry.name) // no fatal err
		diffErrors1 := diffAnalyzer.Errors()
		require.Equal(t, len(diffErrors1), entry.expectedErrNumWithoutStopOnErr, "test: %s", entry.name)
		require.Contains(t, diffErrors1[0].Error().Error(), entry.firstErrStr, "test: %s", entry.name)

		// run with stopOnError
		diffAnalyzerStopsOnError, connsDiff2, err2 := constructAnalyzerAndGetDiffFromDirPaths(true, entry.format, entry.dir1, entry.dir2)
		require.Nil(t, err2, "test: %s", entry.name)         // no fatal err
		require.Empty(t, connsDiff2, "test: %s", entry.name) // when running with severe error and stopOnError the result must be empty
		diffErrors2 := diffAnalyzerStopsOnError.Errors()
		require.Equal(t, len(diffErrors2), entry.expectedErrNumWithStopOnErr, "test: %s", entry.name)
		require.Contains(t, diffErrors2[0].Error().Error(), entry.firstErrStr, "test: %s", entry.name)
	}
}

func TestWarningsOnly(t *testing.T) {
	// testing behavior with warnings, both analyzer (with and without stopOnError) are expected to run regularly
	// and produce a result, we expect to see same number in DiffErrors array (warnings in our case) for both analyzers
	cases := []testErrEntry{
		{
			name:        "dir 1 warning, has no yamls",
			dir1:        filepath.Join("bad_yamls", "subdir2"),
			dir2:        "ipblockstest",
			firstErrStr: "no yaml files found",
		},

		{
			name:        "dir 1 warning, has no netpols",
			dir1:        "k8s_ingress_test",
			dir2:        "k8s_ingress_test_new",
			firstErrStr: "no relevant Kubernetes network policy resources found",
		},
		{
			name: "dir 2 warning, ingress conns are blocked by netpols",
			dir1: "acs-security-demos",
			dir2: "acs-security-demos-new",
			firstErrStr: "Route resource frontend/asset-cache specified workload frontend/asset-cache[Deployment] as a backend," +
				" but network policies are blocking ingress connections from an arbitrary in-cluster source to this workload.",
		},
	}

	for _, entry := range cases {
		diffAnalyzer, connsDiff1, err1 := constructAnalyzerAndGetDiffFromDirPaths(false, entry.format, entry.dir1, entry.dir2)
		require.Nil(t, err1, "test: %s", entry.name)          // no fatal error
		require.NotNil(t, connsDiff1, "test: %s", entry.name) // produced connectivityDiff

		diffAnalyzerStopsOnError, connsDiff2, err2 := constructAnalyzerAndGetDiffFromDirPaths(true, entry.format, entry.dir1, entry.dir2)
		require.Nil(t, err2, "test: %s", entry.name)          // no fatal error
		require.NotNil(t, connsDiff2, "test: %s", entry.name) // produced connectivityDiff

		diffErrors1 := diffAnalyzer.Errors()
		diffErrors2 := diffAnalyzerStopsOnError.Errors()
		require.Equal(t, len(diffErrors1), len(diffErrors2), "test: %s", entry.name)
		require.Contains(t, diffErrors1[0].Error().Error(), entry.firstErrStr, "test: %s", entry.name)
		require.Contains(t, diffErrors2[0].Error().Error(), entry.firstErrStr, "test: %s", entry.name)
	}
}
