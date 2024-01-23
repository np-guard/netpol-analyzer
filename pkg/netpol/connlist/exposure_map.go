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

// addPeersEntireClusterExposure
// if the given src exposed on egress to entire cluster or/and
// the given dst exposed on ingress to  entire cluster
// updates their map entries with the relevant entire cluster exposure data.
// also updates that the peers are checked for entire cluster exposure in the matching sets maps;
// so each such peer's conn is checked and added to exposures map once only in each direction
func (ex exposureMap) addPeersEntireClusterExposure(pe *eval.PolicyEngine, src, dst Peer, ingressSet,
	egressSet map[Peer]bool) (err error) {
	// 1. update egress exposure for the src (if src is a real workload from resources)
	if !src.IsPeerIPType() && src.Name() != common.PodInRepNs {
		if !egressSet[src] {
			egressSet[src] = true
			err = ex.addPeerXgressEntireClusterExp(pe, src, false)
			if err != nil {
				return err
			}
		}
	}
	// 2. update ingress exposure for the dst
	if !dst.IsPeerIPType() && dst.Name() != common.PodInRepNs {
		if !ingressSet[dst] {
			ingressSet[dst] = true
			err = ex.addPeerXgressEntireClusterExp(pe, dst, true)
		}
	}
	return err
}

// addPeerXgressEntireClusterExp checks and adds (if exists) ingress/egress entire cluster exposure for peer
func (ex exposureMap) addPeerXgressEntireClusterExp(pe *eval.PolicyEngine, peer Peer, isIngress bool) error {
	exposed, err := pe.IsPeerExposedToEntireCluster(peer, isIngress)
	if err != nil {
		return err
	}
	if !exposed {
		return nil
	}
	// exposed
	if _, ok := ex[peer]; !ok {
		ex.initiatePeerEntry(peer)
	}
	conn, err := pe.GetPeerXgressEntireClusterConn(peer, isIngress)
	if err != nil {
		return err
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
	if _, ok := ex[peer]; !ok {
		ex.initiatePeerEntry(peer)
	}
	protected, err := pe.IsPeerProtected(peer, isIngress)
	if err != nil {
		return err
	}
	if !protected {
		return nil // if the peer is not protected, we don't need to store any connection data
	}

	allowedConnSet, ok := allowedConnections.(*common.ConnectionSet)
	if !ok { // should not get here
		return errors.New(netpolerrors.ConversionToConnectionSetErr)
	}
	// protected peer
	// this connection is between a representative peer and the real peer

	// check if the connection is contained in an entire cluster connection; if yes skip; if not store the connection data
	contained, err := connectionContainedInEntireClusterConn(pe, peer, allowedConnSet, isIngress)
	if err != nil {
		return err
	}
	if contained {
		return nil // skip
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
	exposed, err := pe.IsPeerExposedToEntireCluster(peer, isIngress)
	if err != nil {
		return false, err
	}
	if !exposed {
		return false, nil
	}
	// exposed
	generalConn, err := pe.GetPeerXgressEntireClusterConn(peer, isIngress)
	if err != nil {
		return false, err
	}
	return conns.ContainedIn(generalConn), nil
}
