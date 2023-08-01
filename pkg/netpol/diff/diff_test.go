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

var allFormats = []string{common.TextFormat, common.MDFormat, common.CSVFormat}

func TestDiff(t *testing.T) {
	testingEntries := []testEntry{
		{
			firstDirName:  "onlineboutique_workloads",
			secondDirName: "onlineboutique_workloads_changed_netpols",
			formats:       allFormats,
		},
		{
			firstDirName:  "onlineboutique_workloads",
			secondDirName: "onlineboutique_workloads_changed_netpols_and_workloads",
			formats:       allFormats,
		},
		{
			firstDirName:  "onlineboutique_workloads",
			secondDirName: "onlineboutique_workloads_changed_workloads",
			formats:       allFormats,
		},

		{
			firstDirName:  "k8s_ingress_test",
			secondDirName: "k8s_ingress_test_new",
			formats:       allFormats,
		},
		{
			firstDirName:  "acs-security-demos",
			secondDirName: "acs-security-demos-new",
			formats:       allFormats,
		},
	}

	for _, entry := range testingEntries {
		firstDirPath := filepath.Join(testutils.GetTestsDir(), entry.firstDirName)
		secondDirPath := filepath.Join(testutils.GetTestsDir(), entry.secondDirName)
		for _, format := range entry.formats {
			expectedOutputFileName := expectedOutputFilePrefix + entry.firstDirName + "." + format
			expectedOutputFilePath := filepath.Join(secondDirPath, expectedOutputFileName)

			diffAnalyzer := NewDiffAnalyzer(WithOutputFormat(format))
			connsDiff, err := diffAnalyzer.ConnDiffFromDirPaths(firstDirPath, secondDirPath)
			require.Empty(t, err)
			actualOutput, err := diffAnalyzer.ConnectivityDiffToString(connsDiff)
			require.Empty(t, err)
			expectedOutputStr, err := os.ReadFile(expectedOutputFilePath)
			require.Empty(t, err)
			require.Equal(t, actualOutput, string(expectedOutputStr))
		}
	}
}

type testErrEntry struct {
	name            string
	dir1            string
	dir2            string
	errStr          string
	isCaFatalErr    bool
	isCaOtherErr    bool // not fatal
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
			name: "dir 1 with bad netpol - named port error",
			dir1: filepath.Join("bad_netpols", "subdir5"),
			dir2: "ipblockstest",
			errStr: "network policy default/shippingservice-netpol named port error: " +
				"named port is not defined in a selected workload shippingservice",
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
			name:         "dir 1 does not exists",
			dir1:         filepath.Join("bad_yamls", "subdir3"),
			dir2:         "ipblockstest",
			errStr:       "error accessing directory:",
			isCaFatalErr: true,
		},
		{
			name:         "dir 1 warning, has no yamls",
			dir1:         filepath.Join("bad_yamls", "subdir2"),
			dir2:         "ipblockstest",
			errStr:       "no yaml files found",
			isCaOtherErr: true,
		},
		{
			name:         "dir 1 warning, has no netpols",
			dir1:         "k8s_ingress_test",
			dir2:         "k8s_ingress_test_new",
			errStr:       "no relevant Kubernetes network policy resources found",
			isCaOtherErr: true,
		},
		{
			name: "dir 2 warning, ingress conns are blocked by netpols",
			dir1: "acs-security-demos",
			dir2: "acs-security-demos-new",
			errStr: "Route resource frontend/asset-cache specified workload frontend/asset-cache[Deployment] as a backend," +
				" but network policies are blocking ingress connections from an arbitrary in-cluster source to this workload.",
			isCaOtherErr: true,
		},
	}

	for _, entry := range testingErrEntries {
		var diffAnalyzer *DiffAnalyzer
		if entry.format != "" {
			diffAnalyzer = NewDiffAnalyzer(WithOutputFormat(entry.format), WithStopOnError())
		} else {
			diffAnalyzer = NewDiffAnalyzer(WithStopOnError())
		}
		firstDirPath := filepath.Join(testutils.GetTestsDir(), entry.dir1)
		secondDirPath := filepath.Join(testutils.GetTestsDir(), entry.dir2)
		connsDiff, err := diffAnalyzer.ConnDiffFromDirPaths(firstDirPath, secondDirPath)
		diffErrors := diffAnalyzer.Errors()
		if entry.isCaFatalErr {
			require.Nil(t, connsDiff)
			require.Contains(t, err.Error(), entry.errStr)
			require.Contains(t, diffErrors[0].Error().Error(), entry.errStr)
			require.True(t, errors.As(diffErrors[0].Error(), &caErrType))
			continue
		}
		if entry.isCaOtherErr {
			require.Nil(t, err) // no fatal error
			require.Contains(t, diffErrors[0].Error().Error(), entry.errStr)
			require.True(t, errors.As(diffErrors[0].Error(), &caErrType))
			continue
		}
		require.Nil(t, err)
		require.NotNil(t, connsDiff)
		_, err = diffAnalyzer.ConnectivityDiffToString(connsDiff)
		diffErrors = diffAnalyzer.Errors()
		if entry.isFormattingErr {
			require.Equal(t, err.Error(), entry.errStr)
			require.Equal(t, diffErrors[0].Error().Error(), entry.errStr)
			require.True(t, errors.As(diffErrors[0].Error(), &formattingErrType))
			continue
		}
		require.Nil(t, err)
	}
}
