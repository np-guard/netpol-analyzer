package connlist

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/testutils"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/scan"

	"github.com/stretchr/testify/require"
)

var analyzer = NewConnlistAnalyzer()
var analyzerWithStopOnError = NewConnlistAnalyzer(WithStopOnError())

// TestConnList tests the output of ConnlistFromDirPath() for valid input resources
func TestConnList(t *testing.T) {
	testNames := []string{"ipblockstest", "onlineboutique", "onlineboutique_workloads",
		"minikube_resources", "online_boutique_workloads_no_ns"}
	expectedOutputFileName := "connlist_output.txt"
	generateActualOutput := false
	for _, testName := range testNames {
		path := filepath.Join(testutils.GetTestsDir(), testName)
		expectedOutputFile := filepath.Join(path, expectedOutputFileName)
		res, err := analyzer.ConnlistFromDirPath(path)
		if err != nil {
			t.Fatalf("Test %s: TestConnList FromDir err: %v", testName, err)
		}
		actualOutput := analyzer.ConnectionsListToString(res)

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

func TestConnlistAnalyzerMalformedYamlDoc(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "bad_yamls", "document_with_syntax_error.yaml")
	res, err := analyzer.ConnlistFromDirPath(dirPath)
	// MalformedYamlDocError is not fatal, thus not returned without stopOnErr
	// analysis is able to parse some deployments before the bad one, thus can produce connectivity output
	require.Nil(t, err)
	require.NotEmpty(t, res)

	// MalformedYamlDocError is severe, thus returned with stopOnErr
	res1, err1 := analyzerWithStopOnError.ConnlistFromDirPath(dirPath)
	require.NotNil(t, err1)
	require.Empty(t, res1)
	malformedYamlDocError := &scan.MalformedYamlDocError{}
	require.True(t, errors.As(err1, &malformedYamlDocError))
}

func TestConnlistAnalyzerYAMLDocNotK8sResource(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "bad_yamls", "not_a_k8s_resource.yaml")
	res, err := analyzer.ConnlistFromDirPath(dirPath)
	require.NotNil(t, err)
	require.Empty(t, res)
	res1, err1 := analyzerWithStopOnError.ConnlistFromDirPath(dirPath)
	require.NotNil(t, err1)
	require.Empty(t, res1)
}

func TestConnlistAnalyzerBadDirDoesNotExist(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "bad_yamls", "subdir3") // doesn't exist
	res, err := analyzer.ConnlistFromDirPath(dirPath)
	badDir := &scan.FailedAccessingDirError{}
	require.True(t, errors.As(err, &badDir))
	require.Empty(t, res)
}

func TestConnlistAnalyzerBadDirNoYamls(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "bad_yamls", "subdir2") // no yamls
	res, err := analyzer.ConnlistFromDirPath(dirPath)

	// TODO: should noK8sResourcesFound / noYamls be fatal to force processing?
	// is it ok to return a custom error as fatal error?
	require.NotNil(t, err)
	require.Empty(t, res)

	// in both cases returns errors.New("cannot produce connectivity list without k8s workloads")
	// this "type" of error does not stop processing, so reaching err within getConnectionsList function
	res1, err1 := analyzerWithStopOnError.ConnlistFromDirPath(dirPath)
	require.NotNil(t, err1)
	require.Empty(t, res1)
}

func TestWithFocusWorkload(t *testing.T) {
	analyzer1 := NewConnlistAnalyzer(WithFocusWorkload("emailservice"))
	dirPath := filepath.Join(testutils.GetTestsDir(), "onlineboutique_workloads")
	res, err := analyzer1.ConnlistFromDirPath(dirPath)
	require.Len(t, res, 2)
	require.Nil(t, err)
}
