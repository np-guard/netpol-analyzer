package common

// NetpolError holds information about a single error/warning that occurred during running
// connectivity analysis command (list or diff)
type NetpolError interface {
	IsFatal() bool
	IsSevere() bool
	Error() error
	Location() string
}

// The actual ingress controller pod is usually unknown and not available in the input resources for the analysis.
const IngressPodName = "ingress-controller"

// SpecificIngressControllersNs is a list of specific namespaces that may be used as the ingress-controller namespace
var SpecificIngressControllersNs = []string{"ingress-nginx", "openshift-ingress-operator"}

// diff format common const
const (
	DotHeader  = "digraph {"
	DotClosing = "}"
)
