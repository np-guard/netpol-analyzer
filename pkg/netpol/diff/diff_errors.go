package diff

// diffGeneratingError - DiffError that may arise while producing the connectivity diff report
type diffGeneratingError struct {
	err    error
	fatal  bool
	severe bool
}

type connectionsAnalyzingError struct {
	origErr error
}

type resultFormattingError struct {
	origErr error
}

type handlingIPpeersError struct {
	origErr error
}

///////////////////////////
// diffGeneratingError implements DiffError interface

// IsFatal returns whether the error is considered fatal (no further processing is possible)
// diffGeneratingError errors are always fatal
func (e *diffGeneratingError) IsFatal() bool {
	return true
}

// IsSevere returns whether the error is considered severe
func (e *diffGeneratingError) IsSevere() bool {
	return false
}

func (e *diffGeneratingError) Location() string {
	return ""
}

func (e *diffGeneratingError) Error() error {
	return e.err
}

///////////////

func (e *resultFormattingError) Error() string {
	return e.origErr.Error()
}

func (e *connectionsAnalyzingError) Error() string {
	return e.origErr.Error()
}

func (e *handlingIPpeersError) Error() string {
	return e.origErr.Error()
}

// constructors
func newResultFormattingError(err error) *diffGeneratingError {
	return &diffGeneratingError{err: &resultFormattingError{err}, fatal: true, severe: false}
}

func newConnectionsAnalyzingError(err error, fatal, severe bool) *diffGeneratingError {
	return &diffGeneratingError{err: &connectionsAnalyzingError{err}, fatal: fatal, severe: severe}
}

func newHandlingIPpeersError(err error) *diffGeneratingError {
	return &diffGeneratingError{err: &handlingIPpeersError{err}, fatal: true, severe: false}
}
