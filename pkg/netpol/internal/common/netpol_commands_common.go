package common

// NetpolError holds information about a single error/warning that occurred during running
// connectivity analysis command (list or diff)
type NetpolError interface {
	IsFatal() bool
	IsSevere() bool
	Error() error
	Location() string
}

// common ingress controllers info (namespaces names and labels)

// The actual ingress controller pod is usually unknown and not available in the input resources for the analysis.
const IngressPodName = "ingress-controller"

// SpecificIngressControllersNsToLabels is a map from specific namespace name that may be used as the
// ingress-controller namespace to map of their identifying labels
var SpecificIngressControllersNsToLabels = map[string]map[string]string{
	"ingress-nginx": {
		"tier":                        "ingress",
		"kubernetes.io/metadata.name": "ingress-nginx",
		"app.kubernetes.io/part-of":   "ingress-nginx",
	},
	"openshift-ingress-operator": {
		"namespace.name":                    "openshift-ingress-operator",
		"kubernetes.io/metadata.name":       "openshift-ingress-operator",
		"network.openshift.io/policy-group": "ingress",
	},
}
