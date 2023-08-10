package connlist

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/common"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/testutils"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/scan"

	"github.com/stretchr/testify/require"
)

func getConnlistFromDirPathRes(stopOnErr bool, path string) (*ConnlistAnalyzer, []Peer2PeerConnection, error) {
	var analyzer *ConnlistAnalyzer
	if stopOnErr {
		analyzer = NewConnlistAnalyzer(WithStopOnError())
	} else {
		analyzer = NewConnlistAnalyzer()
	}

	res, _, err := analyzer.ConnlistFromDirPath(path)
	return analyzer, res, err
}

type testEntry struct {
	testDirName          string
	outputFormats        []string
	generateActualOutput bool // if true, overrides existing expected output file
}

const expectedOutputFileNamePrefix = "connlist_output."

var allFormats = []string{common.TextFormat, common.JSONFormat, common.CSVFormat, common.MDFormat, common.DOTFormat}

// TestConnList tests the output of ConnlistFromDirPath() for valid input resources
func TestConnList(t *testing.T) {
	testingEntries := []testEntry{
		{
			testDirName:   "ipblockstest",
			outputFormats: []string{common.TextFormat},
		},
		{
			testDirName:   "onlineboutique",
			outputFormats: []string{common.JSONFormat, common.MDFormat, common.TextFormat},
		},
		{
			testDirName:   "onlineboutique_workloads",
			outputFormats: []string{common.CSVFormat, common.DOTFormat, common.TextFormat},
		},
		{
			testDirName:   "minikube_resources",
			outputFormats: []string{common.TextFormat},
		},
		{
			testDirName:   "online_boutique_workloads_no_ns",
			outputFormats: []string{common.TextFormat},
		},
		{
			testDirName:   "core_pods_without_host_ip",
			outputFormats: []string{common.TextFormat},
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
			outputFormats: []string{common.TextFormat},
		},
		{
			testDirName:   "test_with_named_ports",
			outputFormats: []string{common.TextFormat},
		},
		{
			testDirName:   "netpol-analysis-example-minimal",
			outputFormats: []string{common.TextFormat},
		},
	}

	for _, entry := range testingEntries {
		dirPath := filepath.Join(testutils.GetTestsDir(), entry.testDirName)
		for _, format := range entry.outputFormats {
			analyzer := NewConnlistAnalyzer(WithOutputFormat(format), WithIncludeJSONManifests())
			res, _, err := analyzer.ConnlistFromDirPath(dirPath)
			require.Nil(t, err)
			output, err := analyzer.ConnectionsListToString(res)
			require.Nil(t, err)
			expectedOutputFileName := expectedOutputFileNamePrefix + format
			expectedOutputFile := filepath.Join(dirPath, expectedOutputFileName)
			if entry.generateActualOutput {
				// update expected output: override expected output with actual output
				err := os.WriteFile(expectedOutputFile, []byte(output), 0o600)
				require.Nil(t, err)
			} else {
				expectedOutput, err := os.ReadFile(expectedOutputFile)
				require.Nil(t, err)
				require.Equal(t, string(expectedOutput), output)
			}
		}
	}
}

func TestConnListWithFocusWorkload(t *testing.T) {
	cases := []struct {
		name                string
		focusWorkload       string
		testDirName         string
		expectedConnsOutput string
		focusedConnsLen     int // result len
	}{
		{
			name:                "focus workload from netpols",
			focusWorkload:       "emailservice",
			testDirName:         "onlineboutique_workloads",
			focusedConnsLen:     1,
			expectedConnsOutput: "default/checkoutservice[Deployment] => default/emailservice[Deployment] : TCP 8080",
		},
		{
			name:            "test with external ingress conns enabled to a single workload in addition to its p2p conns",
			focusWorkload:   "details-v1-79f774bdb9",
			testDirName:     "k8s_ingress_test",
			focusedConnsLen: 13,
			expectedConnsOutput: "0.0.0.0-255.255.255.255 => default/details-v1-79f774bdb9[ReplicaSet] : All Connections\n" +
				"default/details-v1-79f774bdb9[ReplicaSet] => 0.0.0.0-255.255.255.255 : All Connections\n" +
				"default/details-v1-79f774bdb9[ReplicaSet] => default/productpage-v1-6b746f74dc[ReplicaSet] : All Connections\n" +
				"default/details-v1-79f774bdb9[ReplicaSet] => default/ratings-v1-b6994bb9[ReplicaSet] : All Connections\n" +
				"default/details-v1-79f774bdb9[ReplicaSet] => default/reviews-v1-545db77b95[ReplicaSet] : All Connections\n" +
				"default/details-v1-79f774bdb9[ReplicaSet] => default/reviews-v2-7bf8c9648f[ReplicaSet] : All Connections\n" +
				"default/details-v1-79f774bdb9[ReplicaSet] => default/reviews-v3-84779c7bbc[ReplicaSet] : All Connections\n" +
				"default/productpage-v1-6b746f74dc[ReplicaSet] => default/details-v1-79f774bdb9[ReplicaSet] : All Connections\n" +
				"default/ratings-v1-b6994bb9[ReplicaSet] => default/details-v1-79f774bdb9[ReplicaSet] : All Connections\n" +
				"default/reviews-v1-545db77b95[ReplicaSet] => default/details-v1-79f774bdb9[ReplicaSet] : All Connections\n" +
				"default/reviews-v2-7bf8c9648f[ReplicaSet] => default/details-v1-79f774bdb9[ReplicaSet] : All Connections\n" +
				"default/reviews-v3-84779c7bbc[ReplicaSet] => default/details-v1-79f774bdb9[ReplicaSet] : All Connections\n" +
				"{ingress-controller} => default/details-v1-79f774bdb9[ReplicaSet] : TCP 9080",
		},
		{
			name:                "test with external ingress conns enabled to multiple workloads, refined by one workload name",
			testDirName:         "acs-security-demos-added-workloads",
			focusWorkload:       "asset-cache",
			focusedConnsLen:     1,
			expectedConnsOutput: "{ingress-controller} => frontend/asset-cache[Deployment] : TCP 8080",
		},
		{
			name:            "test with external ingress conns enabled to multiple workloads, refined by ingress-controller",
			testDirName:     "acs-security-demos-added-workloads",
			focusWorkload:   "ingress-controller",
			focusedConnsLen: 4,
			expectedConnsOutput: "{ingress-controller} => frontend/asset-cache[Deployment] : TCP 8080\n" +
				"{ingress-controller} => frontend/blog[Deployment] : TCP 8080\n" +
				"{ingress-controller} => frontend/webapp[Deployment] : TCP 8080\n" +
				"{ingress-controller} => zeroday/zeroday[Deployment] : TCP 8080",
		},
	}

	for _, entry := range cases {
		analyzerWithFocusWorkload := NewConnlistAnalyzer(WithFocusWorkload(entry.focusWorkload))
		dirPath := filepath.Join(testutils.GetTestsDir(), entry.testDirName)
		res, _, err := analyzerWithFocusWorkload.ConnlistFromDirPath(dirPath)
		require.Nil(t, err)
		require.Len(t, res, entry.focusedConnsLen)
		out, err := analyzerWithFocusWorkload.ConnectionsListToString(res)
		require.Nil(t, err)
		require.Equal(t, entry.expectedConnsOutput, out)
	}
}

func TestErrNetpolBadCIDR(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "bad_netpols", "subdir1")
	_, res, err := getConnlistFromDirPathRes(false, dirPath)
	fmt.Printf("%v %v", res, err)
	require.Nil(t, res)
	require.NotNil(t, err)
}

func TestErrNetpolBadLabelKey(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "bad_netpols", "subdir2")
	_, res, err := getConnlistFromDirPathRes(false, dirPath)
	fmt.Printf("%v %v", res, err)
	require.Nil(t, res)
	require.NotNil(t, err)
}

func TestErrNetpolBadNetpolRulePeer(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "bad_netpols", "subdir3")
	_, res, err := getConnlistFromDirPathRes(false, dirPath)
	fmt.Printf("%v %v", res, err)
	require.Nil(t, res)
	require.NotNil(t, err)
}

func TestErrNetpolBadNetpolRulePeerEmpty(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "bad_netpols", "subdir4")
	_, res, err := getConnlistFromDirPathRes(false, dirPath)
	fmt.Printf("%v %v", res, err)
	require.Nil(t, res)
	require.NotNil(t, err)
}

func TestErrNetpolBadNetpolNamedPortErrOnIpBlock(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "bad_netpols", "subdir6")
	_, res, err := getConnlistFromDirPathRes(false, dirPath)
	fmt.Printf("%v %v", res, err)
	require.Nil(t, res)
	require.NotNil(t, err)
}

func TestConnlistAnalyzerMalformedYamlDoc(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "bad_yamls", "document_with_syntax_error.yaml")
	analyzer, res, err := getConnlistFromDirPathRes(false, dirPath)
	// MalformedYamlDocError is not fatal, thus not returned
	// analysis is able to parse some deployments before the bad one, thus can produce connectivity output
	require.Nil(t, err)
	require.NotEmpty(t, res)
	require.NotEmpty(t, analyzer.Errors())

	// MalformedYamlDocError is severe, thus returned with stopOnErr
	analyzerWithStopOnError, res1, err1 := getConnlistFromDirPathRes(true, dirPath)
	require.Nil(t, err1)
	require.Empty(t, res1)
	errs := analyzerWithStopOnError.Errors()
	require.NotEmpty(t, errs)
	returnedErr := errs[0]
	malformedYamlDocError := &scan.MalformedYamlDocError{}
	require.True(t, errors.As(returnedErr.Error(), &malformedYamlDocError))
}

func TestConnlistAnalyzerYAMLDocNotK8sResource(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "bad_yamls", "not_a_k8s_resource.yaml")
	analyzer, res, err := getConnlistFromDirPathRes(false, dirPath)
	analyzerWithStopOnError, res1, err1 := getConnlistFromDirPathRes(true, dirPath)
	resErrs1 := analyzerWithStopOnError.Errors()
	resErrs := analyzer.Errors()
	require.Nil(t, err1)
	require.Empty(t, res1)
	require.Nil(t, err)
	require.Empty(t, res)
	require.NotEmpty(t, resErrs)
	require.NotEmpty(t, resErrs1)
}

func TestConnlistAnalyzerBadDirDoesNotExist(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "bad_yamls", "subdir3") // doesn't exist
	_, res, err := getConnlistFromDirPathRes(false, dirPath)
	badDir := &scan.FailedAccessingDirError{}
	require.True(t, errors.As(err, &badDir))
	require.Empty(t, res)
}

func TestConnlistAnalyzerBadDirNoYamls(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "bad_yamls", "subdir2") // no yamls
	analyzer, res, err := getConnlistFromDirPathRes(false, dirPath)
	require.Nil(t, err)
	require.Empty(t, res)
	analyzerWithStopOnError, res1, err1 := getConnlistFromDirPathRes(true, dirPath)
	require.Nil(t, err1)
	require.Empty(t, res1)
	errs := analyzer.Errors()
	errs1 := analyzerWithStopOnError.Errors()
	require.Len(t, errs, 2)  // noK8sResourcesFound + noYamlsFound
	require.Len(t, errs1, 2) // noK8sResourcesFound + noYamlsFound
	firstErr := &scan.NoYamlsFoundError{}
	secondErr := &scan.NoK8sResourcesFoundError{}
	require.True(t, errors.As(errs[0].Error(), &firstErr))
	require.True(t, errors.As(errs[1].Error(), &secondErr))
	require.True(t, errors.As(errs1[0].Error(), &firstErr))
	require.True(t, errors.As(errs1[1].Error(), &secondErr))
}

func TestConnlistAnalyzerBadOutputFormat(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "onlineboutique")
	analyzer := NewConnlistAnalyzer(WithOutputFormat("jpeg"))
	res, _, err1 := analyzer.ConnlistFromDirPath(dirPath)
	require.Nil(t, err1)
	_, err2 := analyzer.ConnectionsListToString(res)
	require.NotNil(t, err2)
}

//	we don't expect to see connections from a workload to itself,
//
// even though the focus workload has different replicas which may connect to each other.
func TestWithFocusWorkloadWithReplicasConnections(t *testing.T) {
	analyzer1 := NewConnlistAnalyzer(WithFocusWorkload("calico-node"))
	dirPath := filepath.Join(testutils.GetTestsDir(), "ipblockstest")
	res, _, err := analyzer1.ConnlistFromDirPath(dirPath)
	require.Len(t, res, 49)
	require.Nil(t, err)
	out, err := analyzer1.ConnectionsListToString(res)
	require.Nil(t, err)
	require.NotContains(t, out, "kube-system/calico-node[DaemonSet] => kube-system/calico-node[DaemonSet] : All Connections")
}
