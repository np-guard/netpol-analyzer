package output

import "os"

// formats supported for output of various commands
const (
	DefaultFormat = "txt"
	TextFormat    = "txt"
	JSONFormat    = "json"
	DOTFormat     = "dot"
	CSVFormat     = "csv"
	MDFormat      = "md"
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
