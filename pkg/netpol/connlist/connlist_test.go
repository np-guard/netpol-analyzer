package connlist

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/testutils"
)

func TestConnList(t *testing.T) {
	testNames := []string{"ipblockstest", "onlineboutique", "onlineboutique_workloads", "minikube_resources"}
	expectedOutputFileName := "connlist_output.txt"
	generateActualOutput := false
	for _, testName := range testNames {
		path := filepath.Join(testutils.GetTestsDir(), testName)
		expectedOutputFile := filepath.Join(path, expectedOutputFileName)
		res, err := FromDir(path, filepath.WalkDir)
		if err != nil {
			t.Fatalf("Test %s: TestConnList FromDir err: %v", testName, err)
		}
		actualOutput := ConnectionsListToString(res)

		if generateActualOutput {
			// update expected output: override expected output with actual output
			if err = os.WriteFile(expectedOutputFile, []byte(actualOutput), 0600); err != nil {
				t.Fatalf("Test %s: TestConnList WriteFile err: %v", testName, err)
			}
		} else {
			// compare actual output to expected output
			expectedStr, err := os.ReadFile(expectedOutputFile)
			if err != nil {
				t.Fatalf("Test %s: TestConnList ReadFile err: %v", testName, err)
			}
			if string(expectedStr) != actualOutput {
				fmt.Printf("%s", actualOutput)
				t.Fatalf("unexpected output result for test %v", testName)
			}
		}
	}
}
