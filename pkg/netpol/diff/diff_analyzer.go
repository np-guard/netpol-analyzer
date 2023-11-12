package diff

import (
	"github.com/np-guard/netpol-analyzer/pkg/netpol/common"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/logger"
)

// A DiffAnalyzer provides API to recursively scan two directories for Kubernetes resources including network policies,
// and get the difference of permitted connectivity between the workloads of the K8s application managed in theses directories.
type DiffAnalyzer struct {
	logger       logger.Logger
	stopOnError  bool
	errors       []DiffError
	outputFormat string
	ref1Name     string
	ref2Name     string
}

// DiffAnalyzerOption is the type for specifying options for DiffAnalyzer,
// using Golang's Options Pattern (https://golang.cafe/blog/golang-functional-options-pattern.html).
type DiffAnalyzerOption func(*DiffAnalyzer)

// WithLogger is a functional option which sets the logger for a DiffAnalyzer to use.
// The provided logger must conform with the package's Logger interface.
func WithLogger(l logger.Logger) DiffAnalyzerOption {
	return func(c *DiffAnalyzer) {
		c.logger = l
	}
}

// WithOutputFormat is a functional option, allowing user to choose the output format txt/csv/md.
func WithOutputFormat(outputFormat string) DiffAnalyzerOption {
	return func(d *DiffAnalyzer) {
		d.outputFormat = outputFormat
	}
}

// WithStopOnError is a functional option which directs DiffAnalyzer to stop any processing after the
// first severe error.
func WithStopOnError() DiffAnalyzerOption {
	return func(d *DiffAnalyzer) {
		d.stopOnError = true
	}
}

// WithArgNames is a functional option that sets the names to be used for the two sets of analyzed resources
// (default is ref1,ref2) in the output reports and log messages.
func WithArgNames(ref1Name, ref2Name string) DiffAnalyzerOption {
	return func(d *DiffAnalyzer) {
		d.ref1Name = ref1Name
		d.ref2Name = ref2Name
	}
}

// Errors returns a slice of DiffError with all warnings and errors encountered during processing.
func (da *DiffAnalyzer) Errors() []DiffError {
	return da.errors
}

// NewDiffAnalyzer creates a new instance of DiffAnalyzer, and applies the provided functional options.
func NewDiffAnalyzer(options ...DiffAnalyzerOption) *DiffAnalyzer {
	// object with default behavior options
	da := &DiffAnalyzer{
		logger:       logger.NewDefaultLogger(),
		stopOnError:  false,
		errors:       []DiffError{},
		outputFormat: common.DefaultFormat,
		ref1Name:     "ref1",
		ref2Name:     "ref2",
	}
	for _, o := range options {
		o(da)
	}
	return da
}
