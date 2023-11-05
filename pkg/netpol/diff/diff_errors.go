package diff

import (
	"errors"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/common"
)

// DiffError holds information about a single error/warning that occurred during
// the generating connectivity diff report
type DiffError common.NetpolError

// diffGeneratingError - DiffError that may arise while producing the connectivity diff report
type diffGeneratingError struct {
	err    error
	fatal  bool
	severe bool
}

type resultFormattingError struct {
	origErr error
}

type handlingIPpeersError struct {
	origErr error
}

type connectivityAnalysisError struct {
	origErr error
	dir1    bool
	dir2    bool
	dirPath string
}

/*type connectivityAnalysisWarning struct {
	origErr error
	dir1    bool
	dir2    bool
	dirPath string
}*/

///////////////////////////
// diffGeneratingError implements DiffError interface

// IsFatal returns whether the error is considered fatal (no further processing is possible)
// diffGeneratingError errors are always fatal
func (e *diffGeneratingError) IsFatal() bool {
	return e.fatal
}

// IsSevere returns whether the error is considered severe
func (e *diffGeneratingError) IsSevere() bool {
	return e.severe
}

func (e *diffGeneratingError) Location() string {
	return ""
}

func (e *diffGeneratingError) Error() error {
	return errors.New(e.err.Error()) // e.err
}

///////////////

func (e *resultFormattingError) Error() string {
	return e.origErr.Error()
}

func (e *handlingIPpeersError) Error() string {
	return e.origErr.Error()
}

func (e *connectivityAnalysisError) Error() string {
	var prefix string
	switch {
	case e.dirPath != "":
		prefix = "at " + e.dirPath + ": "
	case e.dir1:
		prefix = "at dir1: "
	case e.dir2:
		prefix = "at dir2: "
	}
	return prefix + e.origErr.Error()
}

// constructors
func newResultFormattingError(err error) *diffGeneratingError {
	return &diffGeneratingError{err: &resultFormattingError{err}, fatal: true, severe: false}
}

func newHandlingIPpeersError(err error) *diffGeneratingError {
	return &diffGeneratingError{err: &handlingIPpeersError{err}, fatal: true, severe: false}
}

func newConnectivityAnalysisError(err error, dir1, dir2 bool, dirPath string, isSevere, isFatal bool) *diffGeneratingError {
	return &diffGeneratingError{err: &connectivityAnalysisError{
		origErr: err, dir1: dir1, dir2: dir2, dirPath: dirPath}, fatal: isFatal, severe: isSevere}
}
