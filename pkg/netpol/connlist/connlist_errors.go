package connlist

// ConnlistError holds information about a single error/warning that occurred during
// the parsing and connectivity analysis of k8s-app with network policies
type ConnlistError interface {
	IsFatal() bool
	IsSevere() bool
	Error() error
	Location() string
}

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

type connlistAnalyzerWarning struct {
	origErr error
}

func (e *resultFormattingError) Error() string {
	return e.origErr.Error()
}

func (e *resourceEvaluationError) Error() string {
	return e.origErr.Error()
}

func (e *connlistAnalyzerWarning) Error() string {
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
	return &connlistGeneratingError{err: &connlistAnalyzerWarning{err}, fatal: false, severe: false}
}
