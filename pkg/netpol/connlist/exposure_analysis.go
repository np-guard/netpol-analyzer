package connlist

import (
	conn "github.com/np-guard/netpol-analyzer/pkg/netpol/connection"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// exposureMap from peer to its exposure data; map that stores exposure-analysis allowed connections
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

func (e *xgressExposure) PotentialConnectivity() conn.AllowedSet {
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

// gets an exposure map and builds ExposedPeer list while refining exposure connections
// for each peer refines its exposure data as followed:
// * if a peer is not protected by netpols on any direction (ingress/egress) :
// the xgress lists are already empty so will have an empty xgressExp list (output will display not protected)
// * if a peer is protected and exposed to entire cluster on all conns:
// the list will include only this (eliminates other conns with specific namespaces)
// * if a peer is exposed to entire cluster on ingress/egress on a specific connection:
// eliminate exposure-data to specific potential namespaces on same direction and same connection
func buildExposedPeerListFromExposureMap(exposuresMap exposureMap) []ExposedPeer {
	res := make([]ExposedPeer, 0)
	for p, expData := range exposuresMap {
		ingExp := make([]*xgressExposure, 0)
		egExp := make([]*xgressExposure, 0)
		if expData.isIngressProtected {
			ingExp = append(ingExp, loopAndRefineXgressData(expData.ingressExposure)...)
		}
		if expData.isEgressProtected {
			egExp = append(egExp, loopAndRefineXgressData(expData.egressExposure)...)
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

func loopAndRefineXgressData(xgressData []*xgressExposure) []*xgressExposure {
	res := make([]*xgressExposure, 0)
	// helping var
	var entireClusterConn *common.ConnectionSet
	for _, singleConn := range xgressData {
		//  exposed to entire cluster on all conns - result will include this one general exposureConn
		if singleConn.exposedToEntireCluster && singleConn.potentialConn.IsAllConnections() {
			return []*xgressExposure{singleConn}
		}
		if singleConn.exposedToEntireCluster {
			entireClusterConn = singleConn.potentialConn
		}
		// exposed to specific namespace with connection contained in the connection exposed to any-namespace , skip
		if !singleConn.exposedToEntireCluster && entireClusterConn != nil &&
			singleConn.potentialConn.ContainedIn(entireClusterConn) {
			continue
		}
		res = append(res, singleConn)
	}
	if entireClusterConn != nil {
		// refine result - exclude data to/from specific ns with connection contained in the connection exposed to entire cluster
		// if exists, such data was stored before storing entire cluster connection
		res = refineListConnsContainedInEntireConn(res, entireClusterConn)
	}
	return res
}

// refineConnsWithSameValueFromRes returns the xgressExposure list without specified namespaces items
// having conns contained in the given conns value
// keeps the general connection to entire cluster and other connections which are not contained in it
func refineListConnsContainedInEntireConn(expList []*xgressExposure, conns *common.ConnectionSet) []*xgressExposure {
	res := make([]*xgressExposure, 0)
	for _, singleConn := range expList {
		if singleConn.exposedToEntireCluster ||
			!singleConn.potentialConn.ContainedIn(conns) {
			res = append(res, singleConn)
		}
	}
	return res
}
