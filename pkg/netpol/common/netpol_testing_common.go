package common

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// GenerateActualOutputFile generates actual output file
func GenerateActualOutputFile(t *testing.T, testName, output, filePath string) {
	fp, err := os.Create(filePath)
	require.Nil(t, err, "test %q: error creating file %q", testName, filePath)
	_, err = fp.WriteString(output)
	require.Nil(t, err, "test %q: error writing output to file %q", testName, filePath)
}
