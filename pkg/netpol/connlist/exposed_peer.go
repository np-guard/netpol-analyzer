/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package connlist

import (
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// ExposedPeer captures potential ingress and egress connections data for an exposed Peer
type ExposedPeer interface {
	// ExposedPeer is a peer for which the analysis found some potential exposure info
	ExposedPeer() Peer
	// IsProtectedByIngressNetpols indicates if there are ingress netpols selecting the ExposedPeer
	// if peer is not protected, indicates that the peer is exposed on ingress to the whole world,
	// i.e. exposed to all other peers in the cluster and to any external resource.
	// if peer is not protected by ingress netpols, the IngressExposure list will be empty
	IsProtectedByIngressNetpols() bool
	// IngressExposure is a list of the potential Ingress connections to the ExposedPeer
	IngressExposure() []XgressExposureData
	// IsProtectedByEgressNetpols indicates if there are egress netpols selecting the ExposedPeer
	// if peer is not protected, indicates that the peer is exposed on egress to the whole world
	// i.e. exposed to all other peers in the cluster and to any external resource.
	// if peer is not protected by egress netpols, the EgressExposure list will be empty
	IsProtectedByEgressNetpols() bool
	// EgressExposure is a list of the potential Egress connections from the ExposedPeer
	EgressExposure() []XgressExposureData
}

// XgressExposureData contains the data of potential connectivity for an existing peer in the cluster
// a peer might be exposed to the entire cluster (any-namespace), to any namespace with labels or
// any pod with labels in any-namespace, or any pod with labels in a namespace with labels, or any pod with labels in a specific namespace
type XgressExposureData interface {
	// IsExposedToEntireCluster indicates if the peer is exposed to all namespaces in the cluster for the relevant direction.
	// if peer is exposed to entire cluster, NamespaceLabels and PodLabels will be empty
	IsExposedToEntireCluster() bool
	// NamespaceLabels are label selectors of potential namespaces which the peer might be exposed to
	NamespaceLabels() v1.LabelSelector
	// PodLabels are label selectors of potential pods which the peer might be exposed to
	PodLabels() v1.LabelSelector
	// PotentialConnectivity the potential connectivity of the exposure
	PotentialConnectivity() common.Connection
}

// XgressExposureData combinations:
// 1. IsExposedToEntireCluster : true only when the input policies expose the pod to all namespaces in the cluster.
// -  when IsExposedToEntireCluster is true, NamespaceLabels and PodLabels will be empty.
// - when IsExposedToEntireCluster is false at least one of the NamespaceLabels and PodLabels is not empty.
// 2. combinations of NamespaceLabels and PodLabels :
// - NamespaceLabels is empty and PodLabels is not empty: this would be inferred from a policy rule with an empty namespaceSelector
// and specified non-empty podSelector; this describes a potential connection with a pod matching the
// PodLabels LabelSelector in any namespace in the cluster
// - PodLabels is empty, but the NamespaceLabels not empty: this would be inferred from a rule with podSelector is nil or empty;
// and specified non-empty NamespaceSelector; this describes exposure to all pods in any namespace in the cluster that matches
// the NamespaceLabels
// - PodLabels and NamespaceLabels are both not empty: inferred either from a rule with nil namespaceSelector (NamespaceLabels
// will contain the label of the name of the policy namespace) and a specified not empty PodSelector; or a rule with both specified
// NamespaceSelector and PodSelector; and describes an exposure to any pod in the cluster matching PodLabels and in a
// namespace matching the NamespaceLabels.
// - when PodLabels and NamespaceLabels are both empty, then IsExposedToEntireCluster must be true as described above.
