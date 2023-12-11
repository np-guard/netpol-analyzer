package parser

import (
	"errors"
	"fmt"

	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
)

// FileProcessingError holds all information about a single error/warning that occurred during
// the discovery and processing of the connectivity of a given K8s-app.
type FileProcessingError struct {
	err      error
	filePath string
	lineNum  int  // the line number in filePath where the error originates from (1-based, 0 means unknown)
	docID    int  // the number of the YAML document where the error originates from (0-based, -1 means unknown)
	fatal    bool // a fatal error is not recoverable. Outputs should not be used
	severe   bool // a severe error is recoverable. However, outputs should be used with care
}

type NoK8sWorkloadResourcesFoundError struct {
}

type NoK8sNetworkPolicyResourcesFoundError struct {
}

type MalformedYamlDocError struct {
	origErr error
}

type FailedReadingFileError struct {
	origErr error
}

func (err *NoK8sWorkloadResourcesFoundError) Error() string {
	return netpolerrors.NoK8sWorkloadResourcesFoundErrorStr
}

func (err *NoK8sNetworkPolicyResourcesFoundError) Error() string {
	return netpolerrors.NoK8sNetworkPolicyResourcesFoundErrorStr
}

func (err *MalformedYamlDocError) Error() string {
	return netpolerrors.MalformedYamlDocErrorStr + netpolerrors.ColonSep + err.origErr.Error()
}

func (err *MalformedYamlDocError) Unwrap() error {
	return err.origErr
}

func (err *FailedReadingFileError) Error() string {
	return netpolerrors.FailedReadingFileErrorStr + netpolerrors.ColonSep + err.origErr.Error()
}

func (err *FailedReadingFileError) Unwrap() error {
	return err.origErr
}

// Error returns the actual error
func (e *FileProcessingError) Error() error {
	return e.err
}

// File returns the file in which the error occurred (or an empty string if no file context is available)
func (e *FileProcessingError) File() string {
	return e.filePath
}

// LineNo returns the file's line-number in which the error occurred (or 0 if not applicable)
func (e *FileProcessingError) LineNo() int {
	return e.lineNum
}

// DocumentID returns the file's YAML document ID (0-based) in which the error occurred (or an error if not applicable)
func (e *FileProcessingError) DocumentID() (int, error) {
	if e.docID < 0 {
		return -1, errors.New(netpolerrors.NoDocumentIDErrorStr)
	}
	return e.docID, nil
}

// Location returns file location (filename, line-number, document ID) of an error (or an empty string if not applicable)
func (e *FileProcessingError) Location() string {
	if e.filePath == "" {
		return ""
	}

	suffix := ""
	if e.lineNum > 0 {
		suffix = fmt.Sprintf(", line: %d", e.LineNo())
	}
	if did, err := e.DocumentID(); err == nil {
		suffix += fmt.Sprintf(", document: %d%s", did, suffix)
	}
	return fmt.Sprintf("in file: %s%s", e.File(), suffix)
}

// IsFatal returns whether the error is considered fatal (no further processing is possible)
func (e *FileProcessingError) IsFatal() bool {
	return e.fatal
}

// IsSevere returns whether the error is considered severe
// (further processing is possible, but results may not be useable)
func (e *FileProcessingError) IsSevere() bool {
	return e.severe
}

// --------  Constructors for specific error types ----------------

func noK8sWorkloadResourcesFound() *FileProcessingError {
	return &FileProcessingError{&NoK8sWorkloadResourcesFoundError{}, "", 0, -1, false, true}
}

func noK8sNetworkPolicyResourcesFound() *FileProcessingError {
	return &FileProcessingError{&NoK8sNetworkPolicyResourcesFoundError{}, "", 0, -1, false, false}
}

func malformedYamlDoc(filePath string, lineNum, docID int, err error) *FileProcessingError {
	return &FileProcessingError{&MalformedYamlDocError{err}, filePath, lineNum, docID, false, true}
}

func FailedReadingFile(filePath string, err error) *FileProcessingError {
	return &FileProcessingError{&FailedReadingFileError{err}, filePath, 0, -1, false, true}
}
