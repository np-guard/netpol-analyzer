/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package eval

import (
	"fmt"

	"github.com/np-guard/models/pkg/netset"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval/internal/k8s"
)

// Peer can either represent a Pod or an IP address
type Peer interface {
	// Name returns a peer's name in case the peer is a pod/workload, else it returns an empty string
	Name() string
	// Namespace returns a peer's namespace in case the peer is a pod/workload, else it returns an empty string
	Namespace() string
	// IP returns an IP address string in case peer is IP address, else it returns an empty string
	IP() string
	// IsPeerIPType returns true if  peer is IP address
	IsPeerIPType() bool
	// String returns a string representation of the Peer object
	String() string
	// Kind returns a string of the peer kind in case the peer is a pod/workload, else it returns an empty string
	Kind() string
}

// DisjointPeerIPMap is given two sets of IP type peers, and returns a map from peer-str to its disjoint peers, considering both sets
// for example, if ip-range A from set1 is split to ranges (A1, S2) in the disjoint-blocks computation,
// then in the result map there would be entries for (str(A), str(A1), A1) and for (str(A), str(A2), A2)
func DisjointPeerIPMap(set1, set2 []Peer) (map[string]map[string]Peer, error) {
	res := map[string]map[string]Peer{}
	var ipSet1, ipSet2 []*netset.IPBlock
	var err error
	if ipSet1, err = peerIPSetToIPBlockSet(set1); err != nil {
		return nil, err
	}
	if ipSet2, err = peerIPSetToIPBlockSet(set2); err != nil {
		return nil, err
	}
	disjointIPset := netset.DisjointIPBlocks(ipSet1, ipSet2)

	for _, ipb := range disjointIPset {
		addDisjointIPBlockToMap(ipSet1, ipb, res)
		addDisjointIPBlockToMap(ipSet2, ipb, res)
	}

	return res, nil
}

// addDisjointIPBlockToMap updates input map (from peer-str to its disjoint peers) by adding a new disjoint ip
func addDisjointIPBlockToMap(ipSet []*netset.IPBlock, disjointIP *netset.IPBlock, m map[string]map[string]Peer) {
	for _, ipb1 := range ipSet {
		if disjointIP.IsSubset(ipb1) {
			updatePeerIPMap(m, ipb1, disjointIP)
			break
		}
	}
}

// updatePeerIPMap updates input map (from peer-str to its disjoint peers), given a new disjoint ip (ipb), and its
// associated original ip-range key from the map (ipb1)
func updatePeerIPMap(m map[string]map[string]Peer, ipb1, ipb *netset.IPBlock) {
	ipb1Str := ipb1.ToIPRanges()
	if _, ok := m[ipb1Str]; !ok {
		m[ipb1Str] = map[string]Peer{}
	}
	m[ipb1Str][ipb.ToIPRanges()] = &k8s.IPBlockPeer{IPBlock: ipb}
}

// peerIPSetToIPBlockSet is given as input a list of peers of type ip-block, and returns a list matching IPBlock objects
func peerIPSetToIPBlockSet(peerSet []Peer) ([]*netset.IPBlock, error) {
	res := make([]*netset.IPBlock, len(peerSet))
	for i, p := range peerSet {
		ipBlock, err := peerIPToIPBlock(p)
		if err != nil {
			return nil, err
		}
		res[i] = ipBlock
	}
	return res, nil
}

// peerIPToIPBlock returns an IPBlock object from a Peer object of IP type
func peerIPToIPBlock(p Peer) (*netset.IPBlock, error) {
	peerIP, ok := p.(*k8s.IPBlockPeer)
	if !ok {
		return nil, fmt.Errorf("input peer not IP block: %s", p.String())
	}
	return peerIP.IPBlock, nil
}

func mergeIPBlocksList(inputList []*netset.IPBlock) []*netset.IPBlock {
	if len(inputList) == 0 {
		return []*netset.IPBlock{}
	}
	union := inputList[0].Copy()
	for i := 1; i < len(inputList); i++ {
		union = union.Union(inputList[i])
	}
	return union.Split()
}

// MergePeerIPList is given as input a list of peers of type ip-blocks, and returns a new list of peers
// after merging overlapping/touching ip-blocks
func MergePeerIPList(ipPeers []Peer) ([]Peer, error) {
	ipbList, err := peerIPSetToIPBlockSet(ipPeers)
	if err != nil {
		return nil, err
	}
	mergedList := mergeIPBlocksList(ipbList)
	res := make([]Peer, len(mergedList))
	for i := range mergedList {
		res[i] = &k8s.IPBlockPeer{IPBlock: mergedList[i]}
	}
	return res, nil
}
