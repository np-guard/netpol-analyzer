package utils

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

// Ingress Controller const - the name and namespace of an ingress-controller pod
const (
	//  The actual ingress controller pod is usually unknown and not available in the input resources for the analysis.
	// IngressPodName and IngressPodNamespace are used to represent that pod with those placeholder values for name and namespace.
	IngressPodName      = "ingress-controller"
	IngressPodNamespace = "ingress-controller-ns"
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
