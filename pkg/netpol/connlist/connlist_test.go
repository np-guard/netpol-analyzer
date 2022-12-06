package connlist

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConnList(t *testing.T) {
	testNames := []string{"ipblockstest", "onlineboutique"}
	expectedOutputFileName := "connlist_output.txt"
	for _, testName := range testNames {
		path := filepath.Join(getTestsDir(), testName)
		expectedOutputFile := filepath.Join(path, expectedOutputFileName)
		res, err := FromDir(path)
		if err != nil {
			t.Fatalf("Test %v: TestConnList FromDir err: %v", testName, err)
		}
		expectedStr, err := os.ReadFile(expectedOutputFile)
		if err != nil {
			t.Fatalf("Test %v: TestConnList ReadFile err: %v", testName, err)
		}
		if string(expectedStr) != ConnectionsListToString(res) {
			t.Fatalf("unexpected output result for test %v", testName)
		}
	}
}

func getTestsDir() string {
	currentDir, _ := os.Getwd()
	res := filepath.Join(currentDir, "..", "..", "..", "tests")
	return res
}
