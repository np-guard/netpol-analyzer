package connlist

import (
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// exposureMap from peer to its exposure data; map that stores refined exposure-analysis allowed connections
// which are computed by the connlist analyzer
type exposureMap map[Peer]*peerExposureData

// peerExposureData stores exposure data for a peer
type peerExposureData struct {
	isIngressProtected bool
	isEgressProtected  bool
	ingressExposure    []*xgressExposure
	egressExposure     []*xgressExposure
}

// ----------------------------------------------------
// xgressExposure implements XgressExposureData interface
type xgressExposure struct {
	exposedToEntireCluster bool
	namespaceLabels        map[string]string
	podLabels              map[string]string
	potentialConn          *common.ConnectionSet
}

func (e *xgressExposure) IsExposedToEntireCluster() bool {
	return e.exposedToEntireCluster
}

func (e *xgressExposure) NamespaceLabels() map[string]string {
	return e.namespaceLabels
}

func (e *xgressExposure) PodLabels() map[string]string {
	return e.podLabels
}

func (e *xgressExposure) PotentialConnectivity() common.Connection {
	return e.potentialConn
}

// ----------------------------------------------------
// exposedPeer implements the ExposedPeer interface
type exposedPeer struct {
	peer Peer
	*peerExposureData
}

func (ep *exposedPeer) ExposedPeer() Peer {
	return ep.peer
}

func xgressExposureListToXgressExposureDataList(xgressExp []*xgressExposure) []XgressExposureData {
	res := make([]XgressExposureData, len(xgressExp))
	for i := range xgressExp {
		res[i] = xgressExp[i]
	}
	return res
}

func (ep *exposedPeer) IsProtectedByIngressNetpols() bool {
	return ep.isIngressProtected
}

func (ep *exposedPeer) IngressExposure() []XgressExposureData {
	return xgressExposureListToXgressExposureDataList(ep.ingressExposure)
}

func (ep *exposedPeer) IsProtectedByEgressNetpols() bool {
	return ep.isEgressProtected
}

func (ep *exposedPeer) EgressExposure() []XgressExposureData {
	return xgressExposureListToXgressExposureDataList(ep.egressExposure)
}

// ----------------------------------------------------

// gets an exposure map and builds ExposedPeer slice;
// list of entries of peer and its exposure connections each
func buildExposedPeerListFromExposureMap(exposuresMap exposureMap) []ExposedPeer {
	res := make([]ExposedPeer, 0)
	for p, expData := range exposuresMap {
		ingExp := make([]*xgressExposure, 0)
		egExp := make([]*xgressExposure, 0)
		if expData.isIngressProtected {
			ingExp = append(ingExp, expData.ingressExposure...)
		}
		if expData.isEgressProtected {
			egExp = append(egExp, expData.egressExposure...)
		}
		// final peer's exposure data
		expInfo := &exposedPeer{
			peer: p,
			peerExposureData: &peerExposureData{
				isIngressProtected: expData.isIngressProtected,
				isEgressProtected:  expData.isEgressProtected,
				ingressExposure:    ingExp,
				egressExposure:     egExp,
			},
		}
		res = append(res, expInfo)
	}
	return res
}
