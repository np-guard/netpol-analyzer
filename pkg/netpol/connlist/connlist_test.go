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

func getConnlistFromDirPathRes(stopOnErr bool, path string) (*ConnlistAnalyzer, []Peer2PeerConnection, error) {
	var analyzer *ConnlistAnalyzer
	if stopOnErr {
		analyzer = NewConnlistAnalyzer(WithStopOnError())
	} else {
		analyzer = NewConnlistAnalyzer()
	}

	res, err := analyzer.ConnlistFromDirPath(path)
	return analyzer, res, err
}

// TestConnList tests the output of ConnlistFromDirPath() for valid input resources
func TestConnList(t *testing.T) {
	testNames := []string{"ipblockstest", "onlineboutique", "onlineboutique_workloads",
		"minikube_resources", "online_boutique_workloads_no_ns", "core_pods_without_host_ip"}
	expectedOutputFileName := "connlist_output.txt"
	generateActualOutput := false
	for _, testName := range testNames {
		path := filepath.Join(testutils.GetTestsDir(), testName)
		expectedOutputFile := filepath.Join(path, expectedOutputFileName)
		analyzer, res, err := getConnlistFromDirPathRes(false, path)
		if err != nil {
			t.Fatalf("Test %s: TestConnList FromDir err: %v", testName, err)
		}
		actualOutput, err := analyzer.ConnectionsListToString(res)
		if err != nil {
			t.Fatalf("Test %s:  TestConnList writing output err: %v", testName, err)
		}
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

func TestWithFocusWorkload(t *testing.T) {
	analyzer1 := NewConnlistAnalyzer(WithFocusWorkload("emailservice"))
	dirPath := filepath.Join(testutils.GetTestsDir(), "onlineboutique_workloads")
	res, err := analyzer1.ConnlistFromDirPath(dirPath)
	require.Len(t, res, 2)
	require.Nil(t, err)
}

func TestErrNetpolBadCIDR(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "bad_netpols", "subdir1")
	_, res, err := getConnlistFromDirPathRes(false, dirPath)
	fmt.Printf("%v %v", res, err)
	require.Nil(t, res)
	require.NotNil(t, err)
}

func TestErrNetpolBadLabelKey(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "bad_netpols", "subdir2")
	_, res, err := getConnlistFromDirPathRes(false, dirPath)
	fmt.Printf("%v %v", res, err)
	require.Nil(t, res)
	require.NotNil(t, err)
}

func TestErrNetpolBadNetpolRulePeer(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "bad_netpols", "subdir3")
	_, res, err := getConnlistFromDirPathRes(false, dirPath)
	fmt.Printf("%v %v", res, err)
	require.Nil(t, res)
	require.NotNil(t, err)
}

func TestErrNetpolBadNetpolRulePeerEmpty(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "bad_netpols", "subdir4")
	_, res, err := getConnlistFromDirPathRes(false, dirPath)
	fmt.Printf("%v %v", res, err)
	require.Nil(t, res)
	require.NotNil(t, err)
}

func TestErrNetpolBadNetpolNamedPortErr(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "bad_netpols", "subdir5")
	_, res, err := getConnlistFromDirPathRes(false, dirPath)
	fmt.Printf("%v %v", res, err)
	require.Nil(t, res)
	require.NotNil(t, err)
}

func TestErrNetpolBadNetpolNamedPortErrOnIpBlock(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "bad_netpols", "subdir6")
	_, res, err := getConnlistFromDirPathRes(false, dirPath)
	fmt.Printf("%v %v", res, err)
	require.Nil(t, res)
	require.NotNil(t, err)
}

func TestConnlistAnalyzerMalformedYamlDoc(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "bad_yamls", "document_with_syntax_error.yaml")
	analyzer, res, err := getConnlistFromDirPathRes(false, dirPath)
	// MalformedYamlDocError is not fatal, thus not returned
	// analysis is able to parse some deployments before the bad one, thus can produce connectivity output
	require.Nil(t, err)
	require.NotEmpty(t, res)
	require.NotEmpty(t, analyzer.Errors())

	// MalformedYamlDocError is severe, thus returned with stopOnErr
	analyzerWithStopOnError, res1, err1 := getConnlistFromDirPathRes(true, dirPath)
	require.Nil(t, err1)
	require.Empty(t, res1)
	errs := analyzerWithStopOnError.Errors()
	require.NotEmpty(t, errs)
	returnedErr := errs[0]
	malformedYamlDocError := &scan.MalformedYamlDocError{}
	require.True(t, errors.As(returnedErr.Error(), &malformedYamlDocError))
}

func TestConnlistAnalyzerYAMLDocNotK8sResource(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "bad_yamls", "not_a_k8s_resource.yaml")
	analyzer, res, err := getConnlistFromDirPathRes(false, dirPath)
	analyzerWithStopOnError, res1, err1 := getConnlistFromDirPathRes(true, dirPath)
	resErrs1 := analyzerWithStopOnError.Errors()
	resErrs := analyzer.Errors()
	require.Nil(t, err1)
	require.Empty(t, res1)
	require.Nil(t, err)
	require.Empty(t, res)
	require.NotEmpty(t, resErrs)
	require.NotEmpty(t, resErrs1)
}

func TestConnlistAnalyzerBadDirDoesNotExist(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "bad_yamls", "subdir3") // doesn't exist
	_, res, err := getConnlistFromDirPathRes(false, dirPath)
	badDir := &scan.FailedAccessingDirError{}
	require.True(t, errors.As(err, &badDir))
	require.Empty(t, res)
}

func TestConnlistAnalyzerBadDirNoYamls(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "bad_yamls", "subdir2") // no yamls
	analyzer, res, err := getConnlistFromDirPathRes(false, dirPath)
	require.Nil(t, err)
	require.Empty(t, res)
	analyzerWithStopOnError, res1, err1 := getConnlistFromDirPathRes(true, dirPath)
	require.Nil(t, err1)
	require.Empty(t, res1)
	errs := analyzer.Errors()
	errs1 := analyzerWithStopOnError.Errors()
	require.Len(t, errs, 2)  // noK8sResourcesFound + noYamlsFound
	require.Len(t, errs1, 2) // noK8sResourcesFound + noYamlsFound
	firstErr := &scan.NoYamlsFoundError{}
	secondErr := &scan.NoK8sResourcesFoundError{}
	require.True(t, errors.As(errs[0].Error(), &firstErr))
	require.True(t, errors.As(errs[1].Error(), &secondErr))
	require.True(t, errors.As(errs1[0].Error(), &firstErr))
	require.True(t, errors.As(errs1[1].Error(), &secondErr))
}

func TestWithTextOutputFormat(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "onlineboutique")
	analyzer := NewConnlistAnalyzer(WithOutputFormat("txt"))
	res, err := analyzer.ConnlistFromDirPath(dirPath)
	require.Nil(t, err)
	txtRes, err := analyzer.ConnectionsListToString(res)
	require.Nil(t, err)
	expectedOutputFile := filepath.Join(dirPath, "connlist_output.txt")
	expectedOutput, err := os.ReadFile(expectedOutputFile)
	require.Nil(t, err)
	require.Equal(t, string(expectedOutput), txtRes)
}

func TestWithJSONOutputFormat(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "onlineboutique")
	analyzer := NewConnlistAnalyzer(WithOutputFormat("json"))
	res, err := analyzer.ConnlistFromDirPath(dirPath)
	require.Nil(t, err)
	jsonRes, err := analyzer.ConnectionsListToString(res)
	require.Nil(t, err)
	expectedOutputFile := filepath.Join(dirPath, "connlist_output.json")
	expectedOutput, err := os.ReadFile(expectedOutputFile)
	require.Nil(t, err)
	require.Equal(t, string(expectedOutput), jsonRes)
}

func TestWithDOTOutputFormat(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "onlineboutique_workloads")
	analyzer := NewConnlistAnalyzer(WithOutputFormat("dot"))
	res, err := analyzer.ConnlistFromDirPath(dirPath)
	require.Nil(t, err)
	dotRes, err := analyzer.ConnectionsListToString(res)
	require.Nil(t, err)
	expectedOutputFile := filepath.Join(dirPath, "connlist_output.dot")
	expectedOutput, err := os.ReadFile(expectedOutputFile)
	require.Nil(t, err)
	require.Equal(t, string(expectedOutput), dotRes)
}

func TestWithMDOutputFormat(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "onlineboutique")
	analyzer := NewConnlistAnalyzer(WithOutputFormat("md"))
	res, err := analyzer.ConnlistFromDirPath(dirPath)
	require.Nil(t, err)
	mdRes, err := analyzer.ConnectionsListToString(res)
	require.Nil(t, err)
	expectedOutputFile := filepath.Join(dirPath, "connlist_output.md")
	expectedOutput, err := os.ReadFile(expectedOutputFile)
	require.Nil(t, err)
	require.Equal(t, string(expectedOutput), mdRes)
}

func TestWithCSVOutputFormat(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "onlineboutique_workloads")
	analyzer := NewConnlistAnalyzer(WithOutputFormat("csv"))
	res, err := analyzer.ConnlistFromDirPath(dirPath)
	require.Nil(t, err)
	csvRes, err := analyzer.ConnectionsListToString(res)
	require.Nil(t, err)
	expectedOutputFile := filepath.Join(dirPath, "connlist_output.csv")
	expectedOutput, err := os.ReadFile(expectedOutputFile)
	require.Nil(t, err)
	require.Equal(t, string(expectedOutput), csvRes)
}

func TestConnlistAnalyzerBadOutputFormat(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "onlineboutique")
	analyzer := NewConnlistAnalyzer(WithOutputFormat("jpeg"))
	res, err1 := analyzer.ConnlistFromDirPath(dirPath)
	require.Nil(t, err1)
	_, err2 := analyzer.ConnectionsListToString(res)
	require.NotNil(t, err2)
}
