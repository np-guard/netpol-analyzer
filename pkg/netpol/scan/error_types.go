package scan

import (
	"errors"
	"fmt"
	"os"
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

type NoYamlsFoundError struct {
}

type NoK8sResourcesFoundError struct {
}

type NoK8sWorkloadResourcesFoundError struct {
}

type NoK8sNetworkPolicyResourcesFoundError struct {
}

type FailedScanningResource struct {
	resourceType string
	origErr      error
}

type NotK8sResourceError struct {
	origErr error
}

type MalformedYamlDocError struct {
	origErr error
}

type FailedReadingFileError struct {
	origErr error
}

type FailedAccessingDirError struct {
	origErr error
	dirPath string
}

func (err *NoYamlsFoundError) Error() string {
	return "no yaml files found"
}

func (err *NoK8sResourcesFoundError) Error() string {
	return "no relevant Kubernetes resources found"
}

func (err *NoK8sWorkloadResourcesFoundError) Error() string {
	return "no relevant Kubernetes workload resources found"
}

func (err *NoK8sNetworkPolicyResourcesFoundError) Error() string {
	return "no relevant Kubernetes network policy resources found"
}

func (err *FailedScanningResource) Error() string {
	return fmt.Sprintf("error scanning %s resource: %v", err.resourceType, err.origErr)
}

func (err *FailedScanningResource) Unwrap() error {
	return err.origErr
}

func (err *NotK8sResourceError) Error() string {
	return fmt.Sprintf("Yaml document is not a K8s resource: %v", err.origErr)
}

func (err *NotK8sResourceError) Unwrap() error {
	return err.origErr
}

func (err *MalformedYamlDocError) Error() string {
	return fmt.Sprintf("YAML document is malformed: %v", err.origErr)
}

func (err *MalformedYamlDocError) Unwrap() error {
	return err.origErr
}

func (err *FailedReadingFileError) Error() string {
	return fmt.Sprintf("error reading file: %v", err.origErr)
}

func (err *FailedReadingFileError) Unwrap() error {
	return err.origErr
}

func (err *FailedAccessingDirError) Error() string {
	if errors.Is(err.origErr, os.ErrNotExist) {
		return fmt.Sprintf("directory %s was not found", err.dirPath)
	}

	return fmt.Sprintf("failed reading contents of directory: <%s> ", err.dirPath)
}

func (err *FailedAccessingDirError) Unwrap() error {
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
		return -1, errors.New("no document ID is available for this error")
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

func noYamlsFound() *FileProcessingError {
	return &FileProcessingError{&NoYamlsFoundError{}, "", 0, -1, false, false}
}

func noK8sResourcesFound() *FileProcessingError {
	return &FileProcessingError{&NoK8sResourcesFoundError{}, "", 0, -1, false, true}
}

func noK8sWorkloadResourcesFound() *FileProcessingError {
	return &FileProcessingError{&NoK8sWorkloadResourcesFoundError{}, "", 0, -1, false, true}
}

func noK8sNetworkPolicyResourcesFound() *FileProcessingError {
	return &FileProcessingError{&NoK8sNetworkPolicyResourcesFoundError{}, "", 0, -1, false, false}
}

func failedScanningResource(resourceType, filePath string, err error) *FileProcessingError {
	return &FileProcessingError{&FailedScanningResource{resourceType, err}, filePath, 0, -1, false, false}
}

func notK8sResource(filePath string, docID int, err error) *FileProcessingError {
	return &FileProcessingError{&NotK8sResourceError{err}, filePath, 0, docID, false, false}
}

func malformedYamlDoc(filePath string, lineNum, docID int, err error) *FileProcessingError {
	return &FileProcessingError{&MalformedYamlDocError{err}, filePath, lineNum, docID, false, true}
}

func failedReadingFile(filePath string, err error) *FileProcessingError {
	return &FileProcessingError{&FailedReadingFileError{err}, filePath, 0, -1, false, true}
}

func failedAccessingDir(dirPath string, err error, isSubDir bool) *FileProcessingError {
	return &FileProcessingError{&FailedAccessingDirError{origErr: err, dirPath: dirPath}, dirPath, 0, -1, !isSubDir, true}
}
