package connlist

import (
	"errors"

	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// this file contains functions on exposureMap

// appendPeerXgressExposureData updates a peer's entry in the map with new ingress/egress exposure data
func (ex exposureMap) appendPeerXgressExposureData(peer Peer, expData *xgressExposure, isIngress bool) {
	if isIngress {
		ex[peer].ingressExposure = append(ex[peer].ingressExposure, expData)
	} else {
		ex[peer].egressExposure = append(ex[peer].egressExposure, expData)
	}
}

// addPeerGeneralExposure checks if given peer is not protected on given ingress/egress direction;
// if not protected (no policies selecting it) initialize its data in the map (with unprotected flag)
// if protected (selected by at least one policy) check and add entire cluster exposure on the ingress/egress direction (if exists)
func (ex exposureMap) addPeerGeneralExposure(pe *eval.PolicyEngine, peer Peer, isIngress bool) (err error) {
	added, err := ex.addPeerUnprotectedData(pe, peer, isIngress)
	if err != nil {
		return err
	}
	if !added { // protected peer : check and add entire cluster conns
		err = ex.addPeerXgressEntireClusterExp(pe, peer, isIngress)
	}
	return err
}

// addPeerUnprotectedData getting a peer and a direction; checks if the peer is not protected on that direction;
// if not protected, i.e. not selected by any network-policy in the manifests in the given direction:
// adds the peer to the exposure map and returns an indication that an entry was added to the map
func (ex exposureMap) addPeerUnprotectedData(pe *eval.PolicyEngine, peer Peer, isIngress bool) (bool, error) {
	isProtected, err := pe.IsPeerProtected(peer, isIngress)
	if err != nil {
		return false, err
	}
	_, ok := ex[peer]
	// if the peer is not protected by any policy in the given direction; we want to add an entry to the map
	if !ok && !isProtected {
		if isIngress {
			ex.addNewEntry(peer, notProtected, unknown)
		} else {
			ex.addNewEntry(peer, unknown, notProtected)
		}
		return true, nil
	}
	// else :if an entry exists; update the value in the map according to the result (protected/not protected)
	if ok {
		ex.updatePeerEntryWithCorrectProtectedData(peer, isIngress, isProtected)
	}
	return false, nil
}

func (ex exposureMap) updatePeerEntryWithCorrectProtectedData(peer Peer, isIngress, isProtected bool) {
	if isIngress {
		switch isProtected {
		case true:
			ex[peer].isIngressProtected = protected
		case false:
			ex[peer].isIngressProtected = notProtected
		}
	} else { // egress
		switch isProtected {
		case true:
			ex[peer].isEgressProtected = protected
		case false:
			ex[peer].isEgressProtected = notProtected
		}
	}
}

// addPeerXgressEntireClusterExp checks and adds (if exists) ingress/egress entire cluster exposure for the given peer
// on the given direction
func (ex exposureMap) addPeerXgressEntireClusterExp(pe *eval.PolicyEngine, peer Peer, isIngress bool) error {
	conn, err := pe.GetPeerXgressEntireClusterConn(peer, isIngress)
	if err != nil {
		return err
	}
	if conn.IsEmpty() {
		return nil
	}
	// if there is no map entry for the peer : add new entry
	// exposed to entire cluster: means that there is at least one network-policy exposing the peer to entire cluster
	if _, ok := ex[peer]; !ok {
		if isIngress {
			ex.addNewEntry(peer, protected, unknown)
		} else {
			ex.addNewEntry(peer, unknown, protected)
		}
	}
	// update the entry of the peer with the entire cluster connection
	expData := &xgressExposure{
		exposedToEntireCluster: true,
		namespaceLabels:        nil,
		podLabels:              nil,
		potentialConn:          conn,
	}
	ex.appendPeerXgressExposureData(peer, expData, isIngress)

	return nil
}

// addNewEntry adds a new entry to the map, for the given peer;
func (ex exposureMap) addNewEntry(peer Peer, ingProtected, egProtected int) {
	ex[peer] = &peerExposureData{
		isIngressProtected: ingProtected,
		isEgressProtected:  egProtected,
		ingressExposure:    make([]*xgressExposure, 0),
		egressExposure:     make([]*xgressExposure, 0),
	}
}

// addConnToExposureMap adds a connection and its data to the exposure-analysis map
// finally the map will include refined lists of ingress and egress exposure connections for each workload peer
func (ex exposureMap) addConnToExposureMap(pe *eval.PolicyEngine, allowedConnections common.Connection, src, dst Peer,
	isIngress bool) error {
	peer := src               // real peer
	representativePeer := dst // inferred from netpol rule
	if isIngress {
		peer = dst
		representativePeer = src
	}
	// if peer is not protected return
	isProtected, err := pe.IsPeerProtected(peer, isIngress)
	if err != nil {
		return err
	}
	if !isProtected {
		return nil // if the peer is not protected,i.e. not selected by any network-policy; we don't need to store any connection data
	}

	// protected peer and this connection is between a representative peer and the real peer
	allowedConnSet, ok := allowedConnections.(*common.ConnectionSet)
	if !ok { // should not get here
		return errors.New(netpolerrors.ConversionToConnectionSetErr)
	}
	// check if the connection is contained in an entire cluster connection; if yes skip; if not store the connection data
	contained, err := connectionContainedInEntireClusterConn(pe, peer, allowedConnSet, isIngress)
	if err != nil {
		return err
	}
	if contained {
		return nil // skip
	}
	// the peer is protected, check if peer is in the map; if not initialize an entry
	if _, ok := ex[peer]; !ok {
		if isIngress {
			ex.addNewEntry(peer, protected, unknown)
		} else {
			ex.addNewEntry(peer, unknown, protected)
		}
	}

	nsLabels, err := pe.GetPeerNsLabels(representativePeer)
	if err != nil {
		return err
	}
	// store connection data
	expData := &xgressExposure{
		exposedToEntireCluster: false,
		namespaceLabels:        nsLabels,
		podLabels:              map[string]string{}, // will be empty since in this branch rules with namespaceSelectors only supported
		potentialConn:          allowedConnSet,
	}
	ex.appendPeerXgressExposureData(peer, expData, isIngress)
	return nil
}

// connectionContainedInEntireClusterConn gets a connectionSet between a representative peer and
// a given workload peer (existing in the parsed resources),
// and returns whether the given connectionSet is contained in the peer's exposure to entire cluster
// on the given direction (ingress/egress), or not.
// * if the peer is not exposed to entire cluster on the given direction: return false
// * if the peer is exposed to entire cluster on given direction: return whether the given conn is contained in
// the entire cluster exposed conn (which is the max exposure conn)
func connectionContainedInEntireClusterConn(pe *eval.PolicyEngine, peer Peer, conns *common.ConnectionSet, isIngress bool) (bool, error) {
	generalConn, err := pe.GetPeerXgressEntireClusterConn(peer, isIngress)
	if err != nil {
		return false, err
	}
	if generalConn.IsEmpty() {
		// not exposed to entire cluster on this direction
		return false, nil
	}
	return conns.ContainedIn(generalConn), nil
}

// resolveUnknownProtectedData loops the exposure map and checks if there is a peer with unknown protected data on any direction;
// if yes, gets the peer's data and updates it
// this func is called after computing all connections of a peer,
// and hence after updating its protection data (which was updated on the fly when computing allowed conns).
func (ex exposureMap) resolveUnknownProtectedData(pe *eval.PolicyEngine) error {
	for peer, exData := range ex {
		if exData.isIngressProtected == unknown {
			isProtected, err := pe.IsPeerProtected(peer, true)
			if err != nil {
				return err
			}
			ex.updatePeerEntryWithCorrectProtectedData(peer, true, isProtected)
		}
		if exData.isEgressProtected == unknown {
			isProtected, err := pe.IsPeerProtected(peer, false)
			if err != nil {
				return err
			}
			ex.updatePeerEntryWithCorrectProtectedData(peer, false, isProtected)
		}
	}
	return nil
}
