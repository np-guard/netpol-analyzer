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
// general ingress controller name: used when the policies allow connections from at least both supported ingress controllers
const GeneralIngressControllerName = "ingress-controller"

// openshift ingress controller : used when policies support external ingress access only from an
// openshift ingress-controller's namespace
const OpenshiftIngressControllerName = "opneshift-ingress-controller"

// nginx ingress controller : used when policies support ingress access only from an nginx ingress-controller's namespace
const NginxIngressControllerName = "nginx-ingress-controller"

type IngressControllerNamespaceInfo struct {
	ControllerNamespaceName   string            // ingress controller namespace name may be used
	ControllerNamespaceLabels map[string]string // identifying labels of this specific namespace which may be used for an
	// ingress controller representation
}

// SpecificIngressControllerToItsNamespaces is a map from specific ingress controller name to its namespaces info
// which may be used as the ingress-controller namespace
var SpecificIngressControllerToItsNamespaces = map[string][]IngressControllerNamespaceInfo{
	NginxIngressControllerName: {
		{
			ControllerNamespaceName:   "nginx-ingress",
			ControllerNamespaceLabels: map[string]string{"kubernetes.io/metadata.name": "nginx-ingress"},
		},
	},
	OpenshiftIngressControllerName: {
		{
			ControllerNamespaceName: "openshift-ingress-operator",
			ControllerNamespaceLabels: map[string]string{
				"namespace.name":                  "openshift-ingress-operator",
				"kubernetes.io/metadata.name":     "openshift-ingress-operator",
				"openshift.io/cluster-monitoring": "true",
			},
		},
		{
			ControllerNamespaceName: "openshift-ingress",
			ControllerNamespaceLabels: map[string]string{
				"namespace.name":                            "openshift-ingress",
				"kubernetes.io/metadata.name":               "openshift-ingress",
				"openshift.io/cluster-monitoring":           "true",
				"network.openshift.io/policy-group":         "ingress",
				"policy-group.network.openshift.io/ingress": "",
				"pod-security.kubernetes.io/enforce":        "privileged",
				"pod-security.kubernetes.io/audit":          "privileged",
				"pod-security.kubernetes.io/warn":           "privileged",
			},
		},
	},
}
