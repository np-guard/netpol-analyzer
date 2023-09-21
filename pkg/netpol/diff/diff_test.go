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
	name            string
	dir1            string
	dir2            string
	errStr          string
	isCaFatalErr    bool
	isCaSevereErr   bool
	isCaWarning     bool
	isFormattingErr bool
	format          string
}

var caErrType = &connectionsAnalyzingError{}     // error returned from a func on the ConnlistAnalyzer object
var formattingErrType = &resultFormattingError{} // error returned from getting/writing output format

func TestDiffErrors(t *testing.T) {
	// following tests will be run with stopOnError, testing err string and diff err type
	testingErrEntries := []testErrEntry{
		{
			name:            "unsupported format",
			dir1:            "onlineboutique_workloads",
			dir2:            "onlineboutique_workloads_changed_netpols",
			format:          "png",
			errStr:          "png output format is not supported.",
			isFormattingErr: true,
		},
		{
			name:         "dir 1 with bad netpol - CIDR error",
			dir1:         filepath.Join("bad_netpols", "subdir1"),
			dir2:         "ipblockstest",
			errStr:       "network policy default/shippingservice-netpol CIDR error: invalid CIDR address: A",
			isCaFatalErr: true,
		},
		{
			name: "dir 2 with bad netpol - label key error",
			dir1: "ipblockstest",
			dir2: filepath.Join("bad_netpols", "subdir2"),
			errStr: "network policy default/shippingservice-netpol selector error: key: Invalid value: \"app@b\": " +
				"name part must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric" +
				" character (e.g. 'MyName',  or 'my.name',  or '123-abc', regex used for validation is '([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]')",
			isCaFatalErr: true,
		},
		{
			name: "dir 1 with bad netpol - bad rule",
			dir1: filepath.Join("bad_netpols", "subdir3"),
			dir2: "ipblockstest",
			errStr: "network policy default/shippingservice-netpol rule NetworkPolicyPeer error: " +
				"cannot have both IPBlock and PodSelector/NamespaceSelector set",
			isCaFatalErr: true,
		},
		{
			name:         "dir 2 with bad netpol - empty rule",
			dir1:         "ipblockstest",
			dir2:         filepath.Join("bad_netpols", "subdir4"),
			errStr:       "network policy default/shippingservice-netpol rule NetworkPolicyPeer error: cannot have empty rule peer",
			isCaFatalErr: true,
		},
		{
			name:         "dir 2 with bad netpol - named port on ipblock error",
			dir1:         "ipblockstest",
			dir2:         filepath.Join("bad_netpols", "subdir6"),
			errStr:       "network policy default/shippingservice-netpol named port error: cannot convert named port for an IP destination",
			isCaFatalErr: true,
		},
		{
			name:        "dir 1 warning, has no yamls",
			dir1:        filepath.Join("bad_yamls", "subdir2"),
			dir2:        "ipblockstest",
			errStr:      "no yaml files found",
			isCaWarning: true,
		},
		{
			name:         "dir 1 does not exists",
			dir1:         filepath.Join("bad_yamls", "subdir3"),
			dir2:         "ipblockstest",
			errStr:       "error accessing directory:",
			isCaFatalErr: true,
		},
		{
			name:          "dir 1 has no k8s resources",
			dir1:          filepath.Join("bad_yamls", "not_a_k8s_resource.yaml"),
			dir2:          "ipblockstest",
			errStr:        "Yaml document is not a K8s resource",
			isCaSevereErr: true, // severe error, stops only if stopOnError = true
		},
		{
			name:          "dir 1 has malformed yaml",
			dir1:          filepath.Join("bad_yamls", "document_with_syntax_error.yaml"),
			dir2:          "ipblockstest",
			errStr:        "YAML document is malformed",
			isCaSevereErr: true, // severe error, stops only if stopOnError = true
		},
		{
			name:        "dir 1 warning, has no netpols",
			dir1:        "k8s_ingress_test",
			dir2:        "k8s_ingress_test_new",
			errStr:      "no relevant Kubernetes network policy resources found",
			isCaWarning: true,
		},
		{
			name: "dir 2 warning, ingress conns are blocked by netpols",
			dir1: "acs-security-demos",
			dir2: "acs-security-demos-new",
			errStr: "Route resource frontend/asset-cache specified workload frontend/asset-cache[Deployment] as a backend," +
				" but network policies are blocking ingress connections from an arbitrary in-cluster source to this workload.",
			isCaWarning: true,
		},
	}

	for _, entry := range testingErrEntries {
		var diffAnalyzer, diffAnalyzerStopsOnError *DiffAnalyzer
		if entry.format != "" {
			diffAnalyzer = NewDiffAnalyzer(WithOutputFormat(entry.format))
			diffAnalyzerStopsOnError = NewDiffAnalyzer(WithStopOnError(), WithOutputFormat(entry.format))
		} else {
			diffAnalyzer = NewDiffAnalyzer()
			diffAnalyzerStopsOnError = NewDiffAnalyzer(WithStopOnError())
		}

		firstDirPath := filepath.Join(testutils.GetTestsDir(), entry.dir1)
		secondDirPath := filepath.Join(testutils.GetTestsDir(), entry.dir2)
		connsDiff1, err1 := diffAnalyzer.ConnDiffFromDirPaths(firstDirPath, secondDirPath)
		connsDiff2, err2 := diffAnalyzerStopsOnError.ConnDiffFromDirPaths(firstDirPath, secondDirPath)
		diffErrors1 := diffAnalyzer.Errors()
		diffErrors2 := diffAnalyzerStopsOnError.Errors()
		if entry.isCaFatalErr { // fatal err , both analyzers behave the same, nil res, not nil err
			require.Nil(t, connsDiff1, "test: %s", entry.name)
			require.Nil(t, connsDiff2, "test: %s", entry.name)
			require.Contains(t, err1.Error(), entry.errStr, "test: %s", entry.name)
			require.Contains(t, err2.Error(), entry.errStr, "test: %s", entry.name)
			require.Contains(t, diffErrors1[0].Error().Error(), entry.errStr, "test: %s", entry.name)
			require.Contains(t, diffErrors2[0].Error().Error(), entry.errStr, "test: %s", entry.name)
			// check err type
			require.True(t, errors.As(diffErrors1[0].Error(), &caErrType), "test: %s", entry.name)
			require.True(t, errors.As(diffErrors2[0].Error(), &caErrType), "test: %s", entry.name)
			continue
		}
		if entry.isCaSevereErr { // severe error not returned in err, but with stopOnError, empty res with it in the errors
			require.Nil(t, err1, "test: %s", entry.name)
			require.Nil(t, err2, "test: %s", entry.name)
			require.False(t, connsDiff1.IsEmpty(), "test: %s", entry.name) // diffAnalyzer did not stop, result not empty
			require.True(t, connsDiff2.IsEmpty(), "test: %s", entry.name)  // diffAnalyzerStopsOnError stops running, returns empty res
			// error appended to diffAnalyzerErrors in both
			require.Contains(t, diffErrors2[0].Error().Error(), entry.errStr, "test: %s", entry.name)
			require.Contains(t, diffErrors1[0].Error().Error(), entry.errStr, "test: %s", entry.name)
			continue
		}
		if entry.isCaWarning { // both don't stop
			require.Nil(t, err1, "test: %s", entry.name)
			require.NotNil(t, connsDiff1, "test: %s", entry.name)
			require.Nil(t, err2, "test: %s", entry.name)
			require.NotNil(t, connsDiff2, "test: %s", entry.name)
			// warning appended to diffAnalyzerErrors in both
			require.Contains(t, diffErrors2[0].Error().Error(), entry.errStr, "test: %s", entry.name)
			require.Contains(t, diffErrors1[0].Error().Error(), entry.errStr, "test: %s", entry.name)
		}
		_, err1 = diffAnalyzer.ConnectivityDiffToString(connsDiff1)
		_, err2 = diffAnalyzerStopsOnError.ConnectivityDiffToString(connsDiff2)
		diffErrors1 = diffAnalyzer.Errors()
		if entry.isFormattingErr { // formating error is fatal , stops both analyzers
			require.Equal(t, err1.Error(), entry.errStr, "test: %s", entry.name)
			require.Equal(t, err2.Error(), entry.errStr, "test: %s", entry.name)
			require.True(t, errors.As(diffErrors1[0].Error(), &formattingErrType), "test: %s", entry.name)
			continue
		}
		require.Nil(t, err1, "test: %s", entry.name)
		require.Nil(t, err2, "test: %s", entry.name)
	}
}
