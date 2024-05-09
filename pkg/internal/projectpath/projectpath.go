/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package projectpath

import (
	"path/filepath"
	"runtime"
)

const dirLevelUp = ".."

var (
	_, b, _, _ = runtime.Caller(0)

	// Root folder of this project
	Root = filepath.Join(filepath.Dir(b), dirLevelUp, dirLevelUp, dirLevelUp)
)
