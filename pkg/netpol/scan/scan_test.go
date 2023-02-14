package scan

import (
	_ "embed"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/testutils"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/logger"

	"github.com/stretchr/testify/require"
)

//go:embed podList.yaml
var podList string

// global scanner object for testing
var scanner = NewResourcesScanner(logger.NewDefaultLogger(), false, filepath.WalkDir)

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
		res, errs := scanner.FilesToObjectsList(path)
		if len(errs) > 0 {
			t.Fatalf("Test %s: TestFilesToObjectsList err: %v", test.testName, errs)
		}
		if len(res) != test.expectedNumOfParsedObjects {
			t.Fatalf("Test %s: unexpected len of parsed k8s objects list: %d", test.testName, len(res))
		}
	}
}

func TestGetYAMLDocumentsFromPath(t *testing.T) {
	testName := "ipblockstest"
	path := filepath.Join(testutils.GetTestsDir(), testName)
	res, _ := scanner.GetYAMLDocumentsFromPath(path)
	if len(res) != 3 {
		t.Fatalf("Test %s: unexpected len of yaml files list: %d", testName, len(res))
	}
}

func TestFilesToObjectsListBadYamlDocument(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "bad_yamls", "document_with_syntax_error.yaml")

	objs, errs := scanner.FilesToObjectsList(dirPath)
	require.Len(t, errs, 1)
	badDoc := &MalformedYamlDocError{}
	require.True(t, errors.As(errs[0].Error(), &badDoc))

	docID, err := errs[0].DocumentID()
	require.Equal(t, 6, docID)
	require.Nil(t, err)

	require.Len(t, objs, 3)
}
func TestFilesToObjectsListBadYamlDocumentFailFast(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "bad_yamls", "document_with_syntax_error.yaml")
	scannerNew := NewResourcesScanner(logger.NewDefaultLogger(), true, filepath.WalkDir)
	objs, errs := scannerNew.FilesToObjectsList(dirPath)
	require.Len(t, errs, 1)
	badDoc := &MalformedYamlDocError{}
	require.True(t, errors.As(errs[0].Error(), &badDoc))

	docID, err := errs[0].DocumentID()
	require.Equal(t, 6, docID)
	require.Nil(t, err)

	require.Empty(t, objs)
}

func TestFilesToObjectsListNoK8sResource(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "bad_yamls", "not_a_k8s_resource.yaml")
	objs, errs := scanner.FilesToObjectsList(dirPath)
	require.Len(t, errs, 2)
	notK8sRes := &NotK8sResourceError{}
	require.True(t, errors.As(errs[0].Error(), &notK8sRes))
	noK8sResourcesFound := &NoK8sResourcesFoundError{}
	require.True(t, errors.As(errs[1].Error(), &noK8sResourcesFound))
	require.Len(t, objs, 0)
}

func TestGetRelevantK8sResourcesNoYAMLs(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "bad_yamls", "subdir2")
	objs, errs := scanner.FilesToObjectsList(dirPath)
	require.Len(t, errs, 2)
	noYamls := &NoYamlsFoundError{}
	require.True(t, errors.As(errs[0].Error(), &noYamls))
	noK8sResourcesFound := &NoK8sResourcesFoundError{}
	require.True(t, errors.As(errs[1].Error(), &noK8sResourcesFound))
	require.Empty(t, objs)
}

func TestGetRelevantK8sResourcesBadDir(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "bad_yamls", "subdir3") // doesn't exist
	objs, errs := scanner.FilesToObjectsList(dirPath)
	require.Len(t, errs, 1)
	badDir := &FailedAccessingDirError{}
	require.True(t, errors.As(errs[0].Error(), &badDir))
	require.Empty(t, objs)
}

func TestFilesToObjectsListWithBadYamls(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "bad_yamls")

	objs, errs := scanner.FilesToObjectsList(dirPath)

	require.Len(t, errs, 2) // malformed yaml + not a k8s resource  - errors
	require.Len(t, objs, 7)
}

func nonRecursiveWalk(root string, fn fs.WalkDirFunc) error {
	err := filepath.WalkDir(root, func(path string, f os.DirEntry, err error) error {
		if err != nil {
			return filepath.SkipDir
		}
		if f == nil || path != root && f.IsDir() {
			return filepath.SkipDir
		}
		return fn(path, f, err)
	})
	return err
}

func TestSearchForManifestsNonRecursiveWalk(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "bad_yamls")
	scannerNew := NewResourcesScanner(logger.NewDefaultLogger(), false, nonRecursiveWalk)
	objs, errs := scannerNew.FilesToObjectsList(dirPath)

	require.Len(t, errs, 2) // malformed yaml + not a k8s resource  - errors
	require.Len(t, objs, 6) // not including obj from subdir4
}
