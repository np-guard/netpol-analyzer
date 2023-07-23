package connlist

import (
	"errors"

	v1 "k8s.io/api/core/v1"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/common"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
)

// Peer2PeerConnection encapsulates the allowed connectivity result between two peers.
type Peer2PeerConnection interface {
	// Src returns the source peer
	Src() eval.Peer
	// Dst returns the destination peer
	Dst() eval.Peer
	// AllProtocolsAndPorts returns true if all ports are allowed for all protocols
	AllProtocolsAndPorts() bool
	// ProtocolsAndPorts returns the set of allowed connections
	ProtocolsAndPorts() map[v1.Protocol][]common.PortRange
}

func RefineConnListByDisjointPeers(conns []Peer2PeerConnection, m map[string]map[string]eval.Peer) ([]Peer2PeerConnection, error) {
	res := []Peer2PeerConnection{}
	for _, p2p := range conns {
		var replacingConns []Peer2PeerConnection
		var err error
		switch {
		case p2p.Src().IsPeerIPType():
			replacingConns, err = refineP2PConnByDisjointPeers(p2p.Src(), true, p2p, m)
		case p2p.Dst().IsPeerIPType():
			replacingConns, err = refineP2PConnByDisjointPeers(p2p.Dst(), false, p2p, m)
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

func refineP2PConnByDisjointPeers(p eval.Peer, isSrc bool, conn Peer2PeerConnection, m map[string]map[string]eval.Peer) (
	[]Peer2PeerConnection, error) {
	replacingPeers, ok := m[p.String()]
	if !ok {
		return nil, errors.New("missing peer from input disjointPeerIPMap")
	}
	res := make([]Peer2PeerConnection, len(replacingPeers))
	i := 0
	for _, newPeer := range replacingPeers {
		if isSrc {
			res[i] = &connection{src: newPeer, dst: conn.Dst(), allConnections: conn.AllProtocolsAndPorts(),
				protocolsAndPorts: conn.ProtocolsAndPorts()}
		} else {
			res[i] = &connection{src: conn.Src(), dst: newPeer, allConnections: conn.AllProtocolsAndPorts(),
				protocolsAndPorts: conn.ProtocolsAndPorts()}
		}
		i += 1
	}
	return res, nil
}
