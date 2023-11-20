package netpolerrors

const (
	// k8s errors
	CidrErrTitle           = "CIDR error"
	SelectorErrTitle       = "selector error"
	RulePeerErrTitle       = "rule NetworkPolicyPeer error"
	EmptyRulePeerErrStr    = "cannot have empty rule peer"
	CombinedRulePeerErrStr = "cannot have both IPBlock and PodSelector/NamespaceSelector set"
	NamedPortErrTitle      = "named port error"
	ConvertNamedPortErrStr = "cannot convert named port for an IP destination"

	// parser errors
	NoK8sWorkloadResourcesFoundErrorStr      = "no relevant Kubernetes workload resources found"
	NoK8sNetworkPolicyResourcesFoundErrorStr = "no relevant Kubernetes network policy resources found"
	MalformedYamlDocErrorStr                 = "YAML document is malformed"
	FailedReadingFileErrorStr                = "error reading file"
	NoDocumentIDErrorStr                     = "no document ID is available for this error"

	// connlist errors
	EmptyConnListErrStr    = " Connectivity map report will be empty."
	NoIngressSourcesErrStr = "The ingress-controller workload was not added to the analysis, since Ingress/Route resources were not found."

	ErrGettingResInfoFromDir = "Error getting resourceInfos from dir path"
)

// NotSupportedPodResourcesErrorStr returns error string of not supported pods with same ownerRef but different labels
func NotSupportedPodResourcesErrorStr(ownerRefName string) string {
	return "Input Pod resources are not supported for connectivity analysis. Found Pods of the same owner " +
		ownerRefName + " but with different set of labels."
}

// WorkloadDoesNotExistErrStr returns error string of missing workload for connlist with focusworkload
func WorkloadDoesNotExistErrStr(workload string) string {
	return "Workload " + workload + " does not exist in the input resources." + EmptyConnListErrStr
}

// FormatNotSupportedErrStr returns error string of a not supported format for connlist or diff results
func FormatNotSupportedErrStr(format string) string {
	return format + " output format is not supported."
}
