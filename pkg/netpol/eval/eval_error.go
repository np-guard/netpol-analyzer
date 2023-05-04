package eval

type ResourcesEvaluationError struct {
	origErr error
}

// IsFatal returns whether the error is considered fatal (no further processing is possible)
func (e *ResourcesEvaluationError) IsFatal() bool {
	return true
}

// IsSevere returns whether the error is considered severe
// (further processing is possible, but results may not be useable)
func (e *ResourcesEvaluationError) IsSevere() bool {
	return false
}

func (e *ResourcesEvaluationError) Location() string {
	return ""
}

func (e *ResourcesEvaluationError) Error() error {
	return e.origErr
}

func newResourcesEvaluationError(err error) *ResourcesEvaluationError {
	return &ResourcesEvaluationError{
		origErr: err,
	}
}
