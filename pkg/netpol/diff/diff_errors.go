package diff

// DiffError holds information about a single error/warning that occurred during
// the generating connectivity diff report
type DiffError interface {
	IsFatal() bool
	IsSevere() bool
	Error() error
	Location() string
}

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
	return e.err
}

///////////////

func (e *resultFormattingError) Error() string {
	return e.origErr.Error()
}

func (e *handlingIPpeersError) Error() string {
	return e.origErr.Error()
}

// constructors
func newResultFormattingError(err error) *diffGeneratingError {
	return &diffGeneratingError{err: &resultFormattingError{err}, fatal: true, severe: false}
}

func newHandlingIPpeersError(err error) *diffGeneratingError {
	return &diffGeneratingError{err: &handlingIPpeersError{err}, fatal: true, severe: false}
}
