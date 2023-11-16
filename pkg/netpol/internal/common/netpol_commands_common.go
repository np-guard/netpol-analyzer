package common

// NetpolError holds information about a single error/warning that occurred during running
// connectivity analysis command (list or diff)
type NetpolError interface {
	IsFatal() bool
	IsSevere() bool
	Error() error
	Location() string
}

// Ingress Controller const - the name and namespace of an ingress-controller pod
const (
	//  The actual ingress controller pod is usually unknown and not available in the input resources for the analysis.
	// IngressPodName and IngressPodNamespace are used to represent that pod with those placeholder values for name and namespace.
	IngressPodName      = "ingress-controller"
	IngressPodNamespace = "ingress-controller-ns"
)

// diff format common const
const (
	DotHeader  = "digraph {"
	DotClosing = "}"
)
