package connlist

// connlistGeneratingError - ConnlistError that may arrise while producing the connections list
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

type ingressAnalyzerConnsBlockedWarning struct {
	origErr error
}

func (e *resultFormattingError) Error() string {
	return e.origErr.Error()
}

func (e *resourceEvaluationError) Error() string {
	return e.origErr.Error()
}

func (e *ingressAnalyzerConnsBlockedWarning) Error() string {
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

func newIngressAnalyzerConnsBlockedWarning(err error) *connlistGeneratingError {
	return &connlistGeneratingError{err: &ingressAnalyzerConnsBlockedWarning{err}, fatal: false, severe: false}
}
