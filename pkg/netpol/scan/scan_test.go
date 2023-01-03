package scan

import (
	_ "embed"
	"path/filepath"
	"testing"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/testutils"
)

//go:embed podList.yaml
var podList string

func TestParseList(t *testing.T) {
	testName := "TestParseList"
	res := parseList([]byte(podList))
	if len(res) != 1 {
		t.Fatalf("Test %s: unexpected len of parsed k8s objects list: %d", testName, len(res))
	}
}

func TestFilesToObjectsList(t *testing.T) {
	tests := []struct {
		testName                   string
		expectedNumOfParsedObjects int
	}{
		{
			testName:                   "onlineboutique_workloads",
			expectedNumOfParsedObjects: 28,
		},
		{
			testName:                   "ipblockstest",
			expectedNumOfParsedObjects: 38,
		},
		{
			testName:                   "workload_resources",
			expectedNumOfParsedObjects: 18,
		},
	}

	for _, test := range tests {
		path := filepath.Join(testutils.GetTestsDir(), test.testName)
		res, err := FilesToObjectsList(path, filepath.WalkDir)
		if err != nil {
			t.Fatalf("Test %s: TestFilesToObjectsList err: %v", test.testName, err)
		}
		if len(res) != test.expectedNumOfParsedObjects {
			t.Fatalf("Test %s: unexpected len of parsed k8s objects list: %d", test.testName, len(res))
		}
	}
}

func TestGetYAMLDocumentsFromPath(t *testing.T) {
	testName := "ipblockstest"
	path := filepath.Join(testutils.GetTestsDir(), testName)
	res := GetYAMLDocumentsFromPath(path, filepath.WalkDir)
	if len(res) != 3 {
		t.Fatalf("Test %s: unexpected len of yaml files list: %d", testName, len(res))
	}
}
