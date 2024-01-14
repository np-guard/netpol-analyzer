package connlist

import "github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"

// ExposedPeer captures potential ingress and egress connections data for an exposed Peer
type ExposedPeer interface {
	// ExposedPeer is a peer for which the analysis found some potential exposure info
	ExposedPeer() Peer 
	IngressExposure() []XgressExposureData
	EgressExposure() []XgressExposureData
}

// XgressExposureData data of potential connectivity for an existing peer to/from a representative peer
type XgressExposureData interface {
	RepresentativePeer() Peer
	PotentialConnectivity() common.AllowedConnectivity
}
