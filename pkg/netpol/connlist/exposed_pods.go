package connlist

import "github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"

// ExposedPeer captures potential ingress and egress connections data for an exposed Peer
type ExposedPeer interface {
	// ExposedPeer is a peer for which the analysis found some potential exposure info
	ExposedPeer() Peer
	// IngressExposure is a list of the potential Ingress connections to the ExposedPeer
	IngressExposure() []XgressExposureData
	// EgressExposure is a list of the potential Egress connections from the ExposedPeer
	EgressExposure() []XgressExposureData
}

// XgressExposureData contains data of potential connectivity for an existing peer to/from a representative peer
type XgressExposureData interface {
	// IsProtectedByNetpols indicates if the exposed peer is protected by any netpol on Ingress/Egress
	// if a peer is not protected by xgress netpols, it will be exposed to entire cluster with all allowed connections
	IsProtectedByNetpols() bool
	// IsExposedToEntireCluster indicates if the peer is exposed to all namespaces in the cluster for the relevant direction
	IsExposedToEntireCluster() bool
	// NamespaceLabels are matchLabels of potential namespaces which the peer might be exposed to
	NamespaceLabels() map[string]string
	// PodLabels are matchLabels of potential pods which the peer might be exposed to
	PodLabels() map[string]string
	// PotentialConnectivity the potential connectivity of the exposure
	PotentialConnectivity() common.AllowedConnectivity
}
