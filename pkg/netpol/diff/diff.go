// The diff package of netpol-analyzer allows producing a k8s connectivity semantic-diff report based on several resources:
// k8s NetworkPolicy, k8s Ingress, openshift Route
// It lists the set of changed/removed/added connections between pair of peers (k8s workloads or ip-blocks).
// The resources can be extracted from two directories containing YAML manifests.
// For more information, see https://github.com/np-guard/netpol-analyzer.
package diff

import (
	"errors"

	v1 "k8s.io/api/core/v1"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/common"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/connlist"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
)

// diffConnectionsLists returns ConnectivityDiff given two Peer2PeerConnection slices and two peers names sets
// it assumes that the input has been refined with disjoint ip-blocks, and merges
// touching ip-blocks in the output where possible
// currently not including diff of workloads with no connections
func diffConnectionsLists(conns1, conns2 []connlist.Peer2PeerConnection,
	peers1, peers2 map[string]bool) (ConnectivityDiff, error) {
	// convert to a map from src-dst full name, to its connections pair (conns1, conns2)
	diffsMap := diffMap{}
	var err error
	for _, c := range conns1 {
		diffsMap.update(getKeyFromP2PConn(c), true, c)
	}
	for _, c := range conns2 {
		diffsMap.update(getKeyFromP2PConn(c), false, c)
	}

	// merge ip-blocks
	diffsMap, err = diffsMap.mergeIPblocks()
	if err != nil {
		return nil, err
	}

	res := &connectivityDiff{
		removedConns:   []*connsPair{},
		addedConns:     []*connsPair{},
		changedConns:   []*connsPair{},
		unchangedConns: []*connsPair{},
	}
	for _, d := range diffsMap {
		switch {
		case d.firstConn != nil && d.secondConn != nil:
			if !equalConns(d.firstConn, d.secondConn) {
				d.diffType = ChangedType
				d.newOrLostSrc, d.newOrLostDst = false, false
				res.changedConns = append(res.changedConns, d)
			} else { // equal - non changed
				d.diffType = UnchangedType
				d.newOrLostSrc, d.newOrLostDst = false, false
				res.unchangedConns = append(res.unchangedConns, d)
			}
		case d.firstConn != nil:
			// removed conn means both Src and Dst exist in peers1, just check if they are not in peers2 too
			d.diffType = RemovedType
			d.updateNewOrLostFields(true, peers2)
			res.removedConns = append(res.removedConns, d)
		case d.secondConn != nil:
			// added conns means Src and Dst are in peers2, check if they didn't exist in peers1 too
			d.diffType = AddedType
			d.updateNewOrLostFields(false, peers1)
			res.addedConns = append(res.addedConns, d)
		default:
			continue
		}
	}

	return res, nil
}

// allowedConnectivity implements the AllowedConnectivity interface
type allowedConnectivity struct {
	allProtocolsAndPorts bool
	protocolsAndPortsMap map[v1.Protocol][]common.PortRange
}

func (a *allowedConnectivity) AllProtocolsAndPorts() bool {
	return a.allProtocolsAndPorts
}

func (a *allowedConnectivity) ProtocolsAndPorts() map[v1.Protocol][]common.PortRange {
	return a.protocolsAndPortsMap
}

// connsPair captures a pair of Peer2PeerConnection from two dir paths
// the src,dst of firstConn and secondConn are assumed to be the same
// with info on the diffType and if any of the peers is lost/new
// (exists only in one dir for cases of removed/added connections)
// connsPair implements the SrcDstDiff interface
type connsPair struct {
	firstConn    connlist.Peer2PeerConnection
	secondConn   connlist.Peer2PeerConnection
	diffType     DiffTypeStr
	newOrLostSrc bool
	newOrLostDst bool
}

func (c *connsPair) Src() Peer {
	if c.diffType == AddedType {
		return c.secondConn.Src()
	}
	return c.firstConn.Src()
}

func (c *connsPair) Dst() Peer {
	if c.diffType == AddedType {
		return c.secondConn.Dst()
	}
	return c.firstConn.Dst()
}

func (c *connsPair) Ref1Connectivity() AllowedConnectivity {
	if c.diffType == AddedType {
		return &allowedConnectivity{
			allProtocolsAndPorts: false,
			protocolsAndPortsMap: map[v1.Protocol][]common.PortRange{},
		}
	}
	return &allowedConnectivity{
		allProtocolsAndPorts: c.firstConn.AllProtocolsAndPorts(),
		protocolsAndPortsMap: c.firstConn.ProtocolsAndPorts(),
	}
}

func (c *connsPair) Ref2Connectivity() AllowedConnectivity {
	if c.diffType == RemovedType {
		return &allowedConnectivity{
			allProtocolsAndPorts: false,
			protocolsAndPortsMap: map[v1.Protocol][]common.PortRange{},
		}
	}
	return &allowedConnectivity{
		allProtocolsAndPorts: c.secondConn.AllProtocolsAndPorts(),
		protocolsAndPortsMap: c.secondConn.ProtocolsAndPorts(),
	}
}

func (c *connsPair) IsSrcNewOrRemoved() bool {
	return c.newOrLostSrc
}

func (c *connsPair) IsDstNewOrRemoved() bool {
	return c.newOrLostDst
}

func (c *connsPair) DiffType() DiffTypeStr {
	return c.diffType
}

// update func of ConnsPair obj, updates the pair with input Peer2PeerConnection, at first or second conn
func (c *connsPair) updateConn(isFirst bool, conn connlist.Peer2PeerConnection) {
	if isFirst {
		c.firstConn = conn
	} else {
		c.secondConn = conn
	}
}

// isSrcOrDstPeerIPType returns whether src (if checkSrc is true) or dst (if checkSrc is false) is of IP type
func (c *connsPair) isSrcOrDstPeerIPType(checkSrc bool) bool {
	var src, dst eval.Peer
	if c.firstConn != nil {
		src = c.firstConn.Src()
		dst = c.firstConn.Dst()
	} else {
		src = c.secondConn.Src()
		dst = c.secondConn.Dst()
	}
	return (checkSrc && src.IsPeerIPType()) || (!checkSrc && dst.IsPeerIPType())
}

func isIngressControllerPeer(peer eval.Peer) bool {
	return peer.Name() == common.IngressPodName
}

// updateNewOrLostFields updates ConnsPair's newOrLostSrc and newOrLostDst values
func (c *connsPair) updateNewOrLostFields(isFirst bool, peersSet map[string]bool) {
	var src, dst eval.Peer
	if isFirst {
		src, dst = c.firstConn.Src(), c.firstConn.Dst()
	} else {
		src, dst = c.secondConn.Src(), c.secondConn.Dst()
	}
	// update src/dst status based on the peersSet , ignore ips/ingress-controller pod
	if !(src.IsPeerIPType() || isIngressControllerPeer(src)) && !peersSet[src.String()] {
		c.newOrLostSrc = true
	}
	if !(dst.IsPeerIPType() || isIngressControllerPeer(dst)) && !peersSet[dst.String()] {
		c.newOrLostDst = true
	}
}

// diffMap captures connectivity-diff as a map from src-dst key to ConnsPair object
type diffMap map[string]*connsPair

// update func of diffMap, updates the map input key and Peer2PeerConnection, at first or second conn
func (d diffMap) update(key string, isFirst bool, c connlist.Peer2PeerConnection) {
	if _, ok := d[key]; !ok {
		d[key] = &connsPair{}
	}
	d[key].updateConn(isFirst, c)
}

// type mapListConnPairs is a map from key (src-or-dst)+conns1+conns2 to []ConnsPair (where dst-or-src is ip-block)
// it is used to group disjoint ip-blocks and merge overlapping/touching ip-blocks when possible
type mapListConnPairs map[string][]*connsPair

const keyElemSep = ";"

// addConnsPair is given ConnsPair with src or dst as ip-block, and updates mapListConnPairs
func (m mapListConnPairs) addConnsPair(c *connsPair, isSrcAnIP bool) error {
	// new key is src+conns1+conns2 if dst is ip, and dst+conns1+conns2 if src is ip
	var srcOrDstKey string
	var p connlist.Peer2PeerConnection
	var peerIP eval.Peer
	if c.firstConn != nil {
		p = c.firstConn
	} else {
		p = c.secondConn
	}
	if isSrcAnIP {
		peerIP = p.Src()
		srcOrDstKey = p.Dst().String()
	} else {
		peerIP = p.Dst()
		srcOrDstKey = p.Src().String()
	}
	if !peerIP.IsPeerIPType() {
		return errors.New("src/dst is not IP type as expected")
	}

	conn1, conn2, err := getConnStringsFromConnsPair(c)
	if err != nil {
		return err
	}

	newKey := srcOrDstKey + keyElemSep + conn1 + keyElemSep + conn2

	if _, ok := m[newKey]; !ok {
		m[newKey] = []*connsPair{}
	}
	m[newKey] = append(m[newKey], c)

	return nil
}

// getConnStringsFromConnsPair returns string representation of connections from the pair at ConnsPair
func getConnStringsFromConnsPair(c *connsPair) (conn1, conn2 string, err error) {
	switch {
	case c.firstConn != nil && c.secondConn != nil:
		conn1 = connlist.GetConnectionSetFromP2PConnection(c.firstConn).String()
		conn2 = connlist.GetConnectionSetFromP2PConnection(c.secondConn).String()
	case c.firstConn != nil:
		conn1 = connlist.GetConnectionSetFromP2PConnection(c.firstConn).String()
	case c.secondConn != nil:
		conn2 = connlist.GetConnectionSetFromP2PConnection(c.secondConn).String()
	default:
		return conn1, conn2, errors.New("unexpected empty ConnsPair")
	}
	return conn1, conn2, nil
}

// getDstOrSrcFromConnsPair returns the src or dst Peer from ConnsPair object
func getDstOrSrcFromConnsPair(c *connsPair, isDst bool) eval.Peer {
	var p connlist.Peer2PeerConnection
	if c.firstConn != nil {
		p = c.firstConn
	} else {
		p = c.secondConn
	}
	if isDst {
		return p.Dst()
	}
	return p.Src()
}

// getKeyFromP2PConn returns the form of `src;dst“ from Peer2PeerConnection object, to be used as key in diffMap
func getKeyFromP2PConn(c connlist.Peer2PeerConnection) string {
	src := c.Src()
	dst := c.Dst()
	return src.String() + keyElemSep + dst.String()
}

func (m mapListConnPairs) mergeBySrcOrDstIPPeers(isDstAnIP bool, d diffMap) error {
	for _, srcOrdstIPgroup := range m {
		ipPeersList := make([]eval.Peer, len(srcOrdstIPgroup))
		for i, c := range srcOrdstIPgroup {
			ipPeersList[i] = getDstOrSrcFromConnsPair(c, isDstAnIP)
		}

		// get a merged set of eval.Peer
		mergedIPblocks, err := eval.MergePeerIPList(ipPeersList)
		if err != nil {
			return err
		}

		// add to res the merged entries
		for _, srcOrdstIP := range mergedIPblocks {
			var conns1, conns2 connlist.Peer2PeerConnection
			if srcOrdstIPgroup[0].firstConn != nil {
				if isDstAnIP {
					conns1 = connlist.NewPeer2PeerConnection(
						srcOrdstIPgroup[0].firstConn.Src(),
						srcOrdstIP,
						srcOrdstIPgroup[0].firstConn.AllProtocolsAndPorts(),
						srcOrdstIPgroup[0].firstConn.ProtocolsAndPorts())
				} else {
					conns1 = connlist.NewPeer2PeerConnection(
						srcOrdstIP,
						srcOrdstIPgroup[0].firstConn.Dst(),
						srcOrdstIPgroup[0].firstConn.AllProtocolsAndPorts(),
						srcOrdstIPgroup[0].firstConn.ProtocolsAndPorts())
				}
				d.update(getKeyFromP2PConn(conns1), true, conns1)
			}
			if srcOrdstIPgroup[0].secondConn != nil {
				if isDstAnIP {
					conns2 = connlist.NewPeer2PeerConnection(
						srcOrdstIPgroup[0].secondConn.Src(),
						srcOrdstIP,
						srcOrdstIPgroup[0].secondConn.AllProtocolsAndPorts(),
						srcOrdstIPgroup[0].secondConn.ProtocolsAndPorts())
				} else {
					conns2 = connlist.NewPeer2PeerConnection(
						srcOrdstIP,
						srcOrdstIPgroup[0].secondConn.Dst(),
						srcOrdstIPgroup[0].secondConn.AllProtocolsAndPorts(),
						srcOrdstIPgroup[0].secondConn.ProtocolsAndPorts())
				}
				d.update(getKeyFromP2PConn(conns2), false, conns2)
			}
		}
	}
	return nil
}

// mergeIPblocks updates d by merging touching disjoint ip-blocks where possible
func (d diffMap) mergeIPblocks() (diffMap, error) {
	dstIP := mapListConnPairs{} // map from key src+conns1+conns2 to []ConnsPair (where dst is ip-block)
	srcIP := mapListConnPairs{} // map from ket dst+conns1+conns2 to []ConnsPair (where src is ip-block)
	res := diffMap{}
	for k, connsPair := range d {
		switch {
		// neither src nor dst is ip-block => keep connsPair as is
		case !connsPair.isSrcOrDstPeerIPType(false) && !connsPair.isSrcOrDstPeerIPType(true):
			res.update(k, true, connsPair.firstConn)
			res.update(k, false, connsPair.secondConn)
			continue
		case connsPair.isSrcOrDstPeerIPType(false): // dst is ip-block
			if err := dstIP.addConnsPair(connsPair, false); err != nil {
				return nil, err
			}
		case connsPair.isSrcOrDstPeerIPType(true):
			if err := srcIP.addConnsPair(connsPair, true); err != nil {
				return nil, err
			}
		default:
			continue // not expecting to get here
		}
	}

	// next, merge lines from dstIP / srcIP where possible, and add to res
	if err := dstIP.mergeBySrcOrDstIPPeers(true, res); err != nil {
		return nil, err
	}
	if err := srcIP.mergeBySrcOrDstIPPeers(false, res); err != nil {
		return nil, err
	}

	return res, nil
}

// checks whether two connlist.Peer2PeerConnection objects are equal
func equalConns(firstConn, secondConn connlist.Peer2PeerConnection) bool {
	// first convert the Peer2PeerConnections to ConnectionSet objects, then compare
	conn1 := connlist.GetConnectionSetFromP2PConnection(firstConn)
	conn2 := connlist.GetConnectionSetFromP2PConnection(secondConn)

	return conn1.Equal(conn2)
}

// connectivityDiff implements the ConnectivityDiff interface
type connectivityDiff struct {
	removedConns   []*connsPair
	addedConns     []*connsPair
	changedConns   []*connsPair
	unchangedConns []*connsPair
}

func connsPairListToSrcDstDiffList(connsPairs []*connsPair) []SrcDstDiff {
	res := make([]SrcDstDiff, len(connsPairs))
	for i := range connsPairs {
		res[i] = connsPairs[i]
	}
	return res
}

func (c *connectivityDiff) RemovedConnections() []SrcDstDiff {
	return connsPairListToSrcDstDiffList(c.removedConns)
}

func (c *connectivityDiff) AddedConnections() []SrcDstDiff {
	return connsPairListToSrcDstDiffList(c.addedConns)
}

func (c *connectivityDiff) ChangedConnections() []SrcDstDiff {
	return connsPairListToSrcDstDiffList(c.changedConns)
}

func (c *connectivityDiff) IsEmpty() bool {
	return len(c.removedConns) == 0 && len(c.addedConns) == 0 && len(c.changedConns) == 0
}

func (c *connectivityDiff) UnchangedConnections() []SrcDstDiff {
	return connsPairListToSrcDstDiffList(c.unchangedConns)
}
