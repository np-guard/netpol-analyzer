package connlist

import (
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// exposureMaps is a struct containing two maps from peer to its exposure data, one for each direction ingress/egress;
// maps that store refined exposure-analysis allowed connections which are computed by the connlist analyzer
type exposureMaps struct {
	ingressExposureMap map[Peer]*peerXgressExposureData
	egressExposureMap  map[Peer]*peerXgressExposureData
}

// peerXgressExposureData store exposure data of a peer on one direction ingress/egress
type peerXgressExposureData struct {
	// isProtected indicates whether the peer is protected by network-policies on the relevant direction or not
	isProtected bool
	// exposureInfo list of the exposure-connections data of the peer on the relevant direction.
	// if isProtected is false (peer is not protected), this field will be empty
	exposureInfo []*xgressExposure
}

// ----------------------------------------------------
// xgressExposure implements XgressExposureData interface
type xgressExposure struct {
	// exposedToEntireCluster indicates if the peer is exposed to all namespaces in the cluster for the relevant direction
	exposedToEntireCluster bool
	// namespaceLabels are matchLabels of potential namespaces which the peer might be exposed to
	namespaceLabels map[string]string
	// podLabels are matchLabels of potential pods which the peer might be exposed to
	podLabels map[string]string
	// potentialConn the potential connectivity of the exposure
	potentialConn *common.ConnectionSet
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
	peer            Peer
	ingressExposure *peerXgressExposureData
	egressExposure  *peerXgressExposureData
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
	return ep.ingressExposure.isProtected
}

func (ep *exposedPeer) IngressExposure() []XgressExposureData {
	return xgressExposureListToXgressExposureDataList(ep.ingressExposure.exposureInfo)
}

func (ep *exposedPeer) IsProtectedByEgressNetpols() bool {
	return ep.egressExposure.isProtected
}

func (ep *exposedPeer) EgressExposure() []XgressExposureData {
	return xgressExposureListToXgressExposureDataList(ep.egressExposure.exposureInfo)
}

// ----------------------------------------------------

// exposureMaps struct contains:
// 1. ingressExposureMap : entries of peer to its ingress exposure-analysis data; which may be:
// - the peer is not protected by ingress netpols
// - the peer is protected by ingress netpols and exposed unsecure to unknown end-points.(exposure-analysis case)
// 2. egressExposureMap : entries of peer to its exposure-analysis data; i.e.:
// - the peer is not protected by egress netpols.
// or - the peer is exposed on egress to unknown end-points
//
// a peer that exists only in one map (one direction); means its protected and exposed securely (to known hosts)
// on the other direction

// buildExposedPeerListFromExposureMaps gets an exposureMaps struct and builds ExposedPeer slice;
// list of entries of peer and its exposure connections each
func buildExposedPeerListFromExposureMaps(exposureMaps *exposureMaps) []ExposedPeer {
	res := make([]ExposedPeer, 0)
	// first loop the ingressExposureMap : for each peer, fill its ingress exposure data
	// and check if it exists also in the egressExposureMap too - get its egress exposure data;
	// otherwise it is protected safely on egress (add default value)
	for p, ingressExpData := range exposureMaps.ingressExposureMap {
		// default value for egress exposure
		egressExposureData := newDefaultXgressExposureData()
		// check existence in egress map
		if egressData, ok := exposureMaps.egressExposureMap[p]; ok {
			egressExposureData = egressData
		}
		// final peer's exposure data
		expInfo := &exposedPeer{
			peer:            p,
			ingressExposure: ingressExpData,
			egressExposure:  egressExposureData,
		}
		res = append(res, expInfo)
	}
	// second loop egressExposureMap and add peers that don't exist in the ingressExposureMap
	for p, egressExpData := range exposureMaps.egressExposureMap {
		// if p exists in the ingress exposure map so already handled, skip
		if _, ok := exposureMaps.ingressExposureMap[p]; ok {
			continue
		}
		expInfo := &exposedPeer{
			peer:            p,
			ingressExposure: newDefaultXgressExposureData(),
			egressExposure:  egressExpData,
		}
		res = append(res, expInfo)
	}
	return res
}

// newDefaultXgressExposureData returns new peerXgressExposureData pointer with default values
func newDefaultXgressExposureData() *peerXgressExposureData {
	return &peerXgressExposureData{
		isProtected:  true,
		exposureInfo: nil,
	}
}
