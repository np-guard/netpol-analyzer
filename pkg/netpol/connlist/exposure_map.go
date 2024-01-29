package connlist

import (
	"errors"

	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// this file contains functions on exposureMap

// initiatePeerEntry initiates an empty entry for the peer in the exposure map
func (ex exposureMap) initiatePeerEntry(peer Peer) {
	ex[peer] = &peerExposureData{
		isIngressProtected: false,
		isEgressProtected:  false,
		ingressExposure:    make([]*xgressExposure, 0),
		egressExposure:     make([]*xgressExposure, 0),
	}
}

// appendPeerXgressExposureData updates a peer's entry in the map with new ingress/egress exposure data
func (ex exposureMap) appendPeerXgressExposureData(peer Peer, expData *xgressExposure, isIngress bool) {
	if isIngress {
		ex[peer].isIngressProtected = true
		ex[peer].ingressExposure = append(ex[peer].ingressExposure, expData)
	} else {
		ex[peer].isEgressProtected = true
		ex[peer].egressExposure = append(ex[peer].egressExposure, expData)
	}
}

// addPeerGeneralExposure checks if given peer is not protected on given ingress/egress direction;
// if not protected initialize its data in the map (with unprotected flag)
// if protected check and add entire cluster exposure on the ingress/egress direction (if exists)
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
// if not protected adds the peer to the exposure map and returns an indication that was added
func (ex exposureMap) addPeerUnprotectedData(pe *eval.PolicyEngine, peer Peer, isIngress bool) (bool, error) {
	protected, err := pe.IsPeerProtected(peer, isIngress)
	if err != nil {
		return false, err
	}
	if !protected {
		if _, ok := ex[peer]; !ok {
			ex.initiatePeerEntry(peer)
		}
		return true, nil
	}
	return false, nil
}

// addPeerXgressEntireClusterExp checks and adds (if exists) ingress/egress entire cluster exposure for the given peer
// on the given direction
func (ex exposureMap) addPeerXgressEntireClusterExp(pe *eval.PolicyEngine, peer Peer, isIngress bool) error {
	conn, err := pe.GetPeerXgressEntireClusterConn(peer, isIngress)
	if err != nil {
		return err
	}
	if conn == nil {
		return nil
	}
	// exposed to entire cluster
	if _, ok := ex[peer]; !ok {
		ex.initiatePeerEntry(peer)
	}
	expData := &xgressExposure{
		exposedToEntireCluster: true,
		namespaceLabels:        nil,
		podLabels:              nil,
		potentialConn:          conn,
	}
	ex.appendPeerXgressExposureData(peer, expData, isIngress)

	return nil
}

// addConnToExposureMap adds a connection and its data to the exposure-analysis map
// finally the map will include refined lists of ingress and egress exposure connections for each workload peer
func (ex exposureMap) addConnToExposureMap(pe *eval.PolicyEngine, allowedConnections common.Connection, src, dst Peer,
	isIngress bool) error {
	peer := src         // real peer
	inferredPeer := dst // inferred from netpol rule
	if isIngress {
		peer = dst
		inferredPeer = src
	}
	// if peer is not protected return
	protected, err := pe.IsPeerProtected(peer, isIngress)
	if err != nil {
		return err
	}
	if !protected {
		return nil // if the peer is not protected, we don't need to store any connection data
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
	// check if peer is in the map; if not initialize an entry
	if _, ok := ex[peer]; !ok {
		ex.initiatePeerEntry(peer)
	}
	// store connection data
	expData := &xgressExposure{
		exposedToEntireCluster: false,
		namespaceLabels:        pe.GetPeerNsLabels(inferredPeer),
		podLabels:              map[string]string{}, // will be empty since in this branch rules with namespaceSelectors only supported
		potentialConn:          allowedConnSet,
	}
	if isIngress {
		ex.appendPeerXgressExposureData(peer, expData, true)
	} else { // egress
		ex.appendPeerXgressExposureData(peer, expData, false)
	}
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
	if generalConn == nil {
		// not exposed to entire cluster on this direction
		return false, nil
	}
	return conns.ContainedIn(generalConn), nil
}
