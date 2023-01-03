package testutils

import (
	"os"
	"path/filepath"
)

const dirLevelUp = ".."

func GetTestsDir() string {
	currentDir, _ := os.Getwd()
	res := filepath.Join(currentDir, dirLevelUp, dirLevelUp, dirLevelUp, "tests")
	return res
}
