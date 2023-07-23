package diff

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/testutils"
)

type testEntry struct {
	firstDirName  string
	secondDirName string
}

const expectedOutputFilePrefix = "diff_output_from_"

func TestDiff(t *testing.T) {
	testingEntries := []testEntry{
		{
			firstDirName:  "onlineboutique_workloads",
			secondDirName: "onlineboutique_workloads_changed_netpols",
		},
		{
			firstDirName:  "onlineboutique_workloads",
			secondDirName: "onlineboutique_workloads_changed_netpols_and_workloads",
		},
		{
			firstDirName:  "onlineboutique_workloads",
			secondDirName: "onlineboutique_workloads_changed_workloads",
		},
	}

	for _, entry := range testingEntries {
		firstDirPath := filepath.Join(testutils.GetTestsDir(), entry.firstDirName)
		secondDirPath := filepath.Join(testutils.GetTestsDir(), entry.secondDirName)
		expectedOutputFileName := expectedOutputFilePrefix + entry.firstDirName
		expectedOutputFilePath := filepath.Join(secondDirPath, expectedOutputFileName)

		diffAnalyzer := NewDiffAnalyzer()
		connsDiff, err := diffAnalyzer.ConnDiffFromDirPaths(firstDirPath, secondDirPath)
		require.Empty(t, err)
		actualOutput, err := connsDiff.String()
		require.Empty(t, err)
		expectedOutputStr, err := os.ReadFile(expectedOutputFilePath)
		require.Empty(t, err)
		require.Equal(t, actualOutput, string(expectedOutputStr))
	}
}
