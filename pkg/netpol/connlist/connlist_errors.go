package connlist

// connlistGeneratingError - ConnlistError that may arrise while producing the connections list
type connlistGeneratingError struct {
	err error
}

type resultFormattingError struct {
	origErr error
}

type resourceEvaluationError struct {
	origErr error
}

func (e *resultFormattingError) Error() string {
	return e.origErr.Error()
}

func (e *resourceEvaluationError) Error() string {
	return e.origErr.Error()
}

// IsFatal returns whether the error is considered fatal (no further processing is possible)
// connlistGeneratingError errors are always fatal
func (e *connlistGeneratingError) IsFatal() bool {
	return true
}

// IsSevere returns whether the error is considered severe
// (further processing is possible, but results may not be useable)
func (e *connlistGeneratingError) IsSevere() bool {
	return false
}

func (e *connlistGeneratingError) Location() string {
	return ""
}

func (e *connlistGeneratingError) Error() error {
	return e.err
}

// constructors

func newResultFormattingError(err error) *connlistGeneratingError {
	return &connlistGeneratingError{&resultFormattingError{err}}
}

func newResourceEvaluationError(err error) *connlistGeneratingError {
	return &connlistGeneratingError{&resourceEvaluationError{err}}
}
