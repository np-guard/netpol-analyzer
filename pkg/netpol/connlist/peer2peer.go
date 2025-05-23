/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connlist

import (
	"errors"

	v1 "k8s.io/api/core/v1"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// Peer2PeerConnection encapsulates the allowed connectivity result between two peers.
type Peer2PeerConnection interface {
	// Src returns the source peer
	Src() Peer
	// Dst returns the destination peer
	Dst() Peer
	// AllProtocolsAndPorts returns true if all ports are allowed for all protocols
	AllProtocolsAndPorts() bool
	// ProtocolsAndPorts returns the set of allowed connections
	ProtocolsAndPorts() map[v1.Protocol][]common.PortRange
}

type Peer eval.Peer

// RefineConnListByDisjointPeers is given as input Peer2PeerConnection slice and a map from peer-str to its disjoint peers,
// and returns a new Peer2PeerConnection slice with refined ip-blocks from their disjoint peers
func RefineConnListByDisjointPeers(conns []Peer2PeerConnection, srcMap, dstMap map[string]map[string]eval.Peer) ([]Peer2PeerConnection,
	error) {
	res := []Peer2PeerConnection{}
	for _, p2p := range conns {
		var replacingConns []Peer2PeerConnection
		var err error
		switch {
		case p2p.Src().IsPeerIPType():
			replacingConns, err = refineP2PConnByDisjointPeers(p2p.Src(), true, p2p, srcMap)
		case p2p.Dst().IsPeerIPType():
			replacingConns, err = refineP2PConnByDisjointPeers(p2p.Dst(), false, p2p, dstMap)
		default:
			replacingConns = []Peer2PeerConnection{p2p}
		}
		if err != nil {
			return nil, err
		}
		res = append(res, replacingConns...)
	}
	return res, nil
}

// refineP2PConnByDisjointPeers is given as input Peer2PeerConnection object, a Peer object of ip-type to be refined,
// a flag isSrc indicating if the ip-type is src or dst, and a map from peer-str to its disjoint peers
// it returns Peer2PeerConnection slice with refined ip-type peers
func refineP2PConnByDisjointPeers(p eval.Peer, isSrc bool, conns Peer2PeerConnection, m map[string]map[string]eval.Peer) (
	[]Peer2PeerConnection, error) {
	replacingPeers, ok := m[p.IP()] // p is of ip-type and the refined ips in the input map are represented by the IPRanges string
	if !ok {
		return nil, errors.New("missing peer from input disjointPeerIPMap")
	}
	res := make([]Peer2PeerConnection, len(replacingPeers))
	i := 0
	for _, newPeer := range replacingPeers {
		if isSrc {
			res[i] = &connection{src: newPeer, dst: conns.Dst(), allConnections: conns.AllProtocolsAndPorts(),
				protocolsAndPorts: conns.ProtocolsAndPorts()}
		} else {
			res[i] = &connection{src: conns.Src(), dst: newPeer, allConnections: conns.AllProtocolsAndPorts(),
				protocolsAndPorts: conns.ProtocolsAndPorts()}
		}
		i += 1
	}
	return res, nil
}

// NewPeer2PeerConnection returns a Peer2PeerConnection object with given src,dst,allConns and conns map
func NewPeer2PeerConnection(src, dst eval.Peer, allConns bool, conns map[v1.Protocol][]common.PortRange) Peer2PeerConnection {
	return &connection{src: src,
		dst:               dst,
		allConnections:    allConns,
		protocolsAndPorts: conns,
	}
}
