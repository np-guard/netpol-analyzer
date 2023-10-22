package common

import "os"

// NetpolError holds information about a single error/warning that occurred during running
// connectivity analysis command (list or diff)
type NetpolError interface {
	IsFatal() bool
	IsSevere() bool
	Error() error
	Location() string
}

// formats supported for output of various commands
const (
	DefaultFormat = "txt"
	TextFormat    = "txt"
	JSONFormat    = "json"
	DOTFormat     = "dot"
	CSVFormat     = "csv"
	MDFormat      = "md"
)

// diff format common const
const (
	DotHeader  = "digraph {"
	DotClosing = "}"
)

// WriteToFile generates output to given file
func WriteToFile(output, filePath string) error {
	fp, err := os.Create(filePath)
	if err != nil {
		return err
	}
	_, err = fp.WriteString(output)
	if err != nil {
		return err
	}
	return nil
}
