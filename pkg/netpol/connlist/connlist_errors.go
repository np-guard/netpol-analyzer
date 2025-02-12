/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connlist

import (
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// ConnlistError holds information about a single error/warning that occurred during
// the parsing and connectivity analysis of k8s-app with network policies
type ConnlistError common.NetpolError

// connlistGeneratingError - ConnlistError that may arise while producing the connections list
type connlistGeneratingError struct {
	err    error
	fatal  bool
	severe bool
}

type resultFormattingError struct {
	origErr error
}

type resourceEvaluationError struct {
	origErr error
}

type connlistAnalyzerWarnError struct {
	origErr error
}

func (e *resultFormattingError) Error() string {
	return e.origErr.Error()
}

func (e *resourceEvaluationError) Error() string {
	return e.origErr.Error()
}

func (e *connlistAnalyzerWarnError) Error() string {
	return e.origErr.Error()
}

// IsFatal returns whether the error is considered fatal (no further processing is possible)
// connlistGeneratingError errors are always fatal
func (e *connlistGeneratingError) IsFatal() bool {
	return e.fatal
}

// IsSevere returns whether the error is considered severe
// (further processing is possible, but results may not be useable)
func (e *connlistGeneratingError) IsSevere() bool {
	return e.severe
}

func (e *connlistGeneratingError) Location() string {
	return ""
}

func (e *connlistGeneratingError) Error() error {
	return e.err
}

// constructors

func newResultFormattingError(err error) *connlistGeneratingError {
	return &connlistGeneratingError{err: &resultFormattingError{err}, fatal: true, severe: false}
}

func newResourceEvaluationError(err error) *connlistGeneratingError {
	return &connlistGeneratingError{err: &resourceEvaluationError{err}, fatal: true, severe: false}
}

func newConnlistAnalyzerWarning(err error) *connlistGeneratingError {
	return &connlistGeneratingError{err: &connlistAnalyzerWarnError{err}, fatal: false, severe: false}
}
