/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

// The Kubernetes API server sets this label on all namespaces
const K8sNsNameLabelKey = "kubernetes.io/metadata.name"
const (
	// according to this: https://network-policy-api.sigs.k8s.io/api-overview/#adminnetworkpolicy-priorities
	// The Priority field in the ANP spec is defined as an integer value within the range 0 to 1000
	MinANPPriority = 0
	MaxANPPriority = 1000
)

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
