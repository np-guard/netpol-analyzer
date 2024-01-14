package connlist

import "github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"

// ExposedPeer captures potential ingress and egress connections data for an exposed Peer
type ExposedPeer interface {
	// ExposedPeer is a peer for which the analysis found some potential exposure info
	ExposedPeer() Peer
	// IngressExposure list of the potential Ingress connections to the ExposedPeer
	IngressExposure() []XgressExposureData
	// EgressExposure list of the potential Egress connections from the ExposedPeer
	EgressExposure() []XgressExposureData
}

// XgressExposureData data of potential connectivity for an existing peer to/from a representative peer
type XgressExposureData interface {
	// IsProtectedByNetpols indicates if the exposed peer is protected by any netpol on Ingress/Egress 
	IsProtectedByNetpols() bool
	// IsExposedToEntireCluster is the peer exposed to all namespaces in the cluster for the relevant direction
	IsExposedToEntireCluster() bool
	// NamespaceLabels the potential namespaces which the peer is exposed to by their labels
	NamespaceLabels() map[string]string
	// PodLabels the potential pods which the peer might be exposed to by labels
	PodLabels() map[string]string
	// PotentialConnectivity the potential connectivity of the exposure
	PotentialConnectivity() common.AllowedConnectivity
}
