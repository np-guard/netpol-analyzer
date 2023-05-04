package connlist

type resultFormattingError struct {
	origErr error
}

// IsFatal returns whether the error is considered fatal (no further processing is possible)
func (e *resultFormattingError) IsFatal() bool {
	return true
}

// IsSevere returns whether the error is considered severe
// (further processing is possible, but results may not be useable)
func (e *resultFormattingError) IsSevere() bool {
	return false
}

func (e *resultFormattingError) Location() string {
	return ""
}

func (e *resultFormattingError) Error() error {
	return e.origErr
}

func newResultFormattingError(err error) *resultFormattingError {
	return &resultFormattingError{
		origErr: err,
	}
}
