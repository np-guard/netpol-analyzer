package connlist

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/testutils"
)

func TestConnList(t *testing.T) {
	testNames := []string{"ipblockstest", "onlineboutique"}
	expectedOutputFileName := "connlist_output.txt"
	for _, testName := range testNames {
		path := filepath.Join(testutils.GetTestsDir(), testName)
		expectedOutputFile := filepath.Join(path, expectedOutputFileName)
		res, err := FromDir(path, filepath.WalkDir)
		if err != nil {
			t.Fatalf("Test %v: TestConnList FromDir err: %v", testName, err)
		}
		expectedStr, err := os.ReadFile(expectedOutputFile)
		if err != nil {
			t.Fatalf("Test %v: TestConnList ReadFile err: %v", testName, err)
		}
		if string(expectedStr) != ConnectionsListToString(res) {
			fmt.Printf("%v", ConnectionsListToString(res))
			t.Fatalf("unexpected output result for test %v", testName)
		}
	}
}
