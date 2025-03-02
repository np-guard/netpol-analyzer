/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package connlist

import (
	"errors"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// this file contains functions on exposureMaps and peerXgressExposureMap

// addPeer adds a new entry to the current map for the given peer; if the peer's key is not in the map
func (m peerXgressExposureMap) addPeer(peer Peer, isProtected bool) {
	if _, ok := m[peer]; !ok {
		m[peer] = &peerXgressExposureData{
			isProtected:  isProtected,
			exposureInfo: []*xgressExposure{},
		}
	}
}

// appendPeerXgressExposureData updates a peer's entry in the relevant map with new exposure data
func (ex *exposureMaps) appendPeerXgressExposureData(peer Peer, expData *xgressExposure, isIngress bool) {
	if isIngress {
		ex.ingressExposureMap[peer].exposureInfo = append(ex.ingressExposureMap[peer].exposureInfo, expData)
	} else { // egress
		ex.egressExposureMap[peer].exposureInfo = append(ex.egressExposureMap[peer].exposureInfo, expData)
	}
}

// addPeerGeneralExposure checks if given peer is not protected on given ingress/egress direction;
// if not protected (no policies selecting it) initialize its data in the relevant map (with unprotected flag)
// if protected (selected by at least one policy) check and add entire cluster exposure on the ingress/egress direction (if exists).
// the unprotected or entire cluster is always first entry of the peer on its relevant map
func (ex *exposureMaps) addPeerGeneralExposure(pe *eval.PolicyEngine, peer Peer, isIngress bool,
	focusConn *common.ConnectionSet) (err error) {
	added, err := ex.addPeerUnprotectedData(pe, peer, isIngress)
	if err != nil {
		return err
	}
	if !added { // protected peer : check and add entire cluster conns
		err = ex.addPeerXgressEntireClusterExp(pe, peer, isIngress, focusConn)
	}
	return err
}

// addPeerUnprotectedData getting a peer and a direction; checks if the peer is not protected on that direction;
// if not protected, i.e. not selected by any network-policy in the manifests in the given direction:
// adds the peer to the xgress exposure map and returns an indication that an entry was added to the map
func (ex *exposureMaps) addPeerUnprotectedData(pe *eval.PolicyEngine, peer Peer, isIngress bool) (bool, error) {
	isProtected, err := pe.IsPeerProtected(peer, isIngress)
	if err != nil {
		return false, err
	}
	if !isProtected {
		ex.addNewEntry(peer, false, isIngress)
		return true, nil
	}
	return false, nil
}

// addPeerXgressEntireClusterExp checks and adds (if exists) ingress/egress entire cluster exposure for the given peer
// on the given direction;
// each entry in the relevant map may has at-most one connection with entire-cluster (which is added by this func)
func (ex *exposureMaps) addPeerXgressEntireClusterExp(pe *eval.PolicyEngine, peer Peer, isIngress bool,
	focusConn *common.ConnectionSet) error {
	conn, err := pe.GetPeerXgressEntireClusterConn(peer, isIngress)
	if err != nil {
		return err
	}
	if conn.IsEmpty() {
		return nil
	}
	// if focus-conn is enabled : if it is contained in the entire-cluster conn, update the general data with it;
	// else - return nil: the peer is not exposed to entire-cluster on the focus-conn
	if focusConn != nil {
		if focusConn.ContainedIn(conn) {
			conn = focusConn // we are interested only in the focus conn
		} else {
			return nil
		}
	}
	// exposed to entire cluster - first entry of the peer
	ex.addNewEntry(peer, true, isIngress)
	expData := &xgressExposure{
		exposedToEntireCluster: true,
		namespaceLabels:        v1.LabelSelector{},
		podLabels:              v1.LabelSelector{},
		potentialConn:          conn,
	}
	ex.appendPeerXgressExposureData(peer, expData, isIngress)
	return nil
}

// addNewEntry adds a new entry to the relevant ingress/egress map for the given peer, if the peer's key is not in the map
func (ex *exposureMaps) addNewEntry(peer Peer, isProtected, isIngress bool) {
	if isIngress {
		ex.ingressExposureMap.addPeer(peer, isProtected)
	} else {
		ex.egressExposureMap.addPeer(peer, isProtected)
	}
}

// addConnToExposureMap adds a new connection data to the matching exposure-analysis map;
// the connection data is inferred from an allowed connection between a real workload peer and a representative peer that was generated
// from a netpol rule
func (ex *exposureMaps) addConnToExposureMap(pe *eval.PolicyEngine, allowedConnections common.Connection, src, dst Peer,
	isIngress bool, focusConn *common.ConnectionSet) error {
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
	// check if the peer is exposed to entire-cluster and if connection equals the entire cluster connection;
	// if allowed connection between src and dst is not equal to the connection with entire cluster, we need to add this connection
	// as an entry in the exposure map
	// more details in the documentation and body  of func `connectionEqualsEntireClusterConn`
	equals, isExposed, err := connectionEqualsEntireClusterConn(pe, peer, allowedConnSet, focusConn, isIngress)
	if err != nil {
		return err
	}
	// skip if:
	// 1. the allowed connection between the real peer and the representative-peer equals the connection to entire-cluster (containment)
	// 2. if the peer is not exposed to entire-cluster and there is no connection (empty allowedConnections) between
	// the peer and representative-peer (no exposure)
	if equals || (!isExposed && allowedConnSet.IsEmpty()) {
		return nil // skip
	}

	// add entry to exposure map if:
	// 1. the allowed connection between the real peer and representative peer is not empty (and not covered by
	// entire-cluster conn) - exposure case
	// 2. if the connection is empty (no conns) and the peer is exposed to entire-cluster - add this empty connection to the exposure map
	// to tell that this representative peer is excluded from `entire-cluster` connection

	// the peer is protected, check if peer is in the relevant map; if not initialize a new entry
	ex.addNewEntry(peer, true, isIngress)

	podLabels, nsLabels, err := pe.GetPeerLabels(representativePeer)
	if err != nil {
		return err
	}
	// store connection data
	expData := &xgressExposure{
		exposedToEntireCluster: false,
		namespaceLabels:        nsLabels,
		podLabels:              podLabels,
		potentialConn:          allowedConnSet,
	}
	ex.appendPeerXgressExposureData(peer, expData, isIngress)
	return nil
}

// connectionEqualsEntireClusterConn gets a connectionSet between a representative peer and
// a given workload peer (existing in the parsed resources),
// and returns :
// 1. whether the given connectionSet equals the peer's exposure to entire cluster
// on the given direction (ingress/egress), or not.
// 2. whether the peer is exposed to entire-cluster (not-empty connection)
// * if the peer is not exposed to entire cluster on the given direction: return false, false
// * if the peer is exposed to entire cluster on given direction: return whether the given conn equals
// the entire cluster exposed conn (which is the max exposure conn) and true as isExposed (peer is exposed to entire cluster)
func connectionEqualsEntireClusterConn(pe *eval.PolicyEngine, peer Peer, conns, focusConn *common.ConnectionSet,
	isIngress bool) (equals, isExposed bool, err error) {
	generalConn, err := pe.GetPeerXgressEntireClusterConn(peer, isIngress)
	if err != nil {
		return false, false, err
	}
	if generalConn.IsEmpty() {
		// not exposed to entire cluster on this direction
		return false, false, nil
	}
	// if focus conn is enabled - check if it is contained in the generalConn - then assign it to GeneralConn
	// (other conns are not meaningful in this case)
	if focusConn != nil && focusConn.ContainedIn(generalConn) {
		generalConn = focusConn // only this conn interests us
	}
	// The conns to a rep. peer should be equal to the entire-cluster's conns, in-order to not be added as
	// a separate entry in the exposure-map.
	// since with AdminNetworkPolicy we might see that a connection to representative peers is containedIn the entire-cluster
	// connection but excludes some ports within a deny rule with higher-priority.
	// see as example the output of tests/exposure_test_with_anp_8
	return conns.Equal(generalConn), true, nil
}
