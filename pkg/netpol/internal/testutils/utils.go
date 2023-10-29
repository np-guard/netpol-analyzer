package testutils

import (
	"os"
	"path/filepath"
)

const (
	dirLevelUp   = ".."
	testsDirName = "tests"
)

func GetTestsDir() string {
	currentDir, _ := os.Getwd()
	res := filepath.Join(currentDir, dirLevelUp, dirLevelUp, dirLevelUp, testsDirName)
	return res
}

func GetTestsDirFromInternalPkg() string {
	currentDir, _ := os.Getwd()
	res := filepath.Join(currentDir, dirLevelUp, dirLevelUp, dirLevelUp, dirLevelUp, dirLevelUp, testsDirName)
	return res
}
