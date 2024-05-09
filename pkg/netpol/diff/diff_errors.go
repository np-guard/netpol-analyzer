/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package diff

import (
	"errors"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
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
	origErr   error
	errPrefix string
	dirPath   string
}

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
		prefix = getErrPrefix(e.dirPath)
	case e.errPrefix != "": // prefix of ref1/ref2 names
		prefix = e.errPrefix
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

func newConnectivityAnalysisError(err error, errPrefix, dirPath string, isSevere, isFatal bool) *diffGeneratingError {
	return &diffGeneratingError{err: &connectivityAnalysisError{
		origErr: err, errPrefix: errPrefix, dirPath: dirPath}, fatal: isFatal, severe: isSevere}
}
