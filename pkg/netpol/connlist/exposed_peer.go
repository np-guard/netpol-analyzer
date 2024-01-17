package connlist

import "github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"

// ExposedPeer captures potential ingress and egress connections data for an exposed Peer
type ExposedPeer interface {
	// ExposedPeer is a peer for which the analysis found some potential exposure info
	ExposedPeer() Peer
	// IsProtectedByIngressNetpols indicates if there are ingress netpols selecting the ExposedPeer
	// if peer is not protected, indicates that the peer is exposed on ingress to the whole world
	// if peer is not protected by ingress netpols, the IngressExposure list will be empty
	IsProtectedByIngressNetpols() bool
	// IngressExposure is a list of the potential Ingress connections to the ExposedPeer
	IngressExposure() []XgressExposureData
	// IsProtectedByEgressNetpols indicates if there are egress netpols selecting the ExposedPeer
	// if peer is not protected, indicates that the peer is exposed on egress to the whole world
	// if peer is not protected by egress netpols, the EgressExposure list will be empty
	IsProtectedByEgressNetpols() bool
	// EgressExposure is a list of the potential Egress connections from the ExposedPeer
	EgressExposure() []XgressExposureData
}

// XgressExposureData contains the data of potential connectivity for an existing peer in the cluster
// a peer might be exposed to the entire cluster (any-namespace), to any namespace with labels or
// any pod with labels in any-namespace, or any pod with labels in a namespace with labels, or any pod with labels in a specific namespace
// TODO: add detailed documentation as to which combinations of values represent which kind of "abstract" node in the output
type XgressExposureData interface {
	// IsExposedToEntireCluster indicates if the peer is exposed to all namespaces in the cluster for the relevant direction
	IsExposedToEntireCluster() bool
	// NamespaceLabels are matchLabels of potential namespaces which the peer might be exposed to
	NamespaceLabels() map[string]string
	// PodLabels are matchLabels of potential pods which the peer might be exposed to
	PodLabels() map[string]string
	// PotentialConnectivity the potential connectivity of the exposure
	PotentialConnectivity() common.AllowedConnectivity
}
