package diff

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/common"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/testutils"
)

type testEntry struct {
	firstDirName      string
	secondDirName     string
	formats           []string
	isErr             bool
	expectedOutputErr string
}

const expectedOutputFilePrefix = "diff_output_from_"

var allFormats = []string{common.TextFormat, common.MDFormat, common.CSVFormat}

func TestDiff(t *testing.T) {
	testingEntries := []testEntry{
		{
			firstDirName:  "onlineboutique_workloads",
			secondDirName: "onlineboutique_workloads_changed_netpols",
			formats:       allFormats,
			isErr:         false,
		},
		{
			firstDirName:  "onlineboutique_workloads",
			secondDirName: "onlineboutique_workloads_changed_netpols_and_workloads",
			formats:       allFormats,
			isErr:         false,
		},
		{
			firstDirName:  "onlineboutique_workloads",
			secondDirName: "onlineboutique_workloads_changed_workloads",
			formats:       allFormats,
			isErr:         false,
		},
		{
			firstDirName:      "onlineboutique_workloads",
			secondDirName:     "onlineboutique_workloads_changed_netpols",
			formats:           []string{"png"},
			isErr:             true,
			expectedOutputErr: "png output format is not supported.",
		},
		{
			firstDirName:  "k8s_ingress_test",
			secondDirName: "k8s_ingress_test_new",
			formats:       allFormats,
			isErr:         false,
		},
		{
			firstDirName:  "acs-security-demos",
			secondDirName: "acs-security-demos-new",
			formats:       allFormats,
			isErr:         false,
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
			if entry.isErr {
				require.Equal(t, err.Error(), entry.expectedOutputErr)
			} else {
				require.Empty(t, err)
				expectedOutputStr, err := os.ReadFile(expectedOutputFilePath)
				require.Empty(t, err)
				require.Equal(t, actualOutput, string(expectedOutputStr))
			}
		}
	}
}
