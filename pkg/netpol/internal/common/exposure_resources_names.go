package common

const (
	// any fake namespace added will start with following prefix for ns name and following pod name
	NsNamePrefix   = "exposure-namespace-"
	PodInExposedNs = "exposure-pod"
	// a pod name that represents belonging to an "arbitrary namespace"
	AllNamespaces = "any-namespace"
)
