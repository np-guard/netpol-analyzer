package connlist

import "github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"

// ExposedPeer captures potential ingress and egress connections data for an exposed Peer
type ExposedPeer interface {
	ExposedPeer() Peer // UnprotectedPeer()
	IngressExposure() []XgressExposureData
	EgressExposure() []XgressExposureData
}

// XgressExposureData data of potential connectivity for an existing peer to/from a representative peer
type XgressExposureData interface {
	RepresentativePeer() Peer
	PotentialConnectivity() common.AllowedConnectivity
}
