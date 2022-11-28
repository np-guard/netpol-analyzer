package connlist

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestConnList(t *testing.T) {
	testNames := []string{"ipblockstest", "onlineboutique"}
	expectedOutputFileName := "connlist_output.txt"
	outputFile := "out.txt"
	for _, testName := range testNames {
		path := filepath.Join(getTestsDir(), testName)
		expectedOutputFile := filepath.Join(path, expectedOutputFileName)
		res, err := FromDir(path)
		if err != nil {
			t.Fatalf("Test %v: TestConnList err: %v", testName, err)
		}
		writeRes(ConnectionsListToString(res), outputFile)
		expectedHash, expectedErr := getFileHashValue(expectedOutputFile)
		actualHash, actualErr := getFileHashValue(outputFile)
		if expectedErr != nil {
			t.Fatalf("error: %v", expectedErr)
		}
		if actualErr != nil {
			t.Fatalf("error: %v", actualErr)
		}
		if expectedHash != actualHash {
			t.Fatalf("unexpected output result for test %v", testName)
		}
		err = os.Remove(outputFile)
		if err != nil {
			t.Logf("could not delete file: %v, err: %v", outputFile, err)
		}
	}
}

func writeRes(res, fileName string) {
	fd, err := os.Create(fileName)
	if err != nil {
		fmt.Printf("error creating file: %v", err)
		return
	}
	b := []byte(res)
	err = os.WriteFile(fileName, b, 0600)
	if err != nil {
		fmt.Printf("error WriteFile: %v", err)
	}
	fd.Close()
}

func getFileHashValue(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func getTestsDir() string {
	currentDir, _ := os.Getwd()
	res := filepath.Join(currentDir, "..", "..", "..", "tests")
	return res
}
