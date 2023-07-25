package diff

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/connlist"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/logger"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/scan"
)

type DiffAnalyzer struct {
	logger      logger.Logger
	stopOnError bool
	// errors        []ConnlistError
	walkFn  scan.WalkFunction
	scanner *scan.ResourcesScanner
	// focusWorkload string
	// outputFormat string
}

func NewDiffAnalyzer() *DiffAnalyzer {
	// object with default behavior options
	da := &DiffAnalyzer{
		logger:      logger.NewDefaultLogger(),
		stopOnError: false,
		//errors:       []ConnlistError{},
		walkFn: filepath.WalkDir,
		//outputFormat: connlist.DefaultFormat,
	}
	// todo : add options
	da.scanner = scan.NewResourcesScanner(da.logger, da.stopOnError, da.walkFn)
	return da
}

func (da DiffAnalyzer) ConnDiffFromDirPaths(dirPath1, dirPath2 string) (ConnectivityDiff, error) {
	caAnalyzer := connlist.NewConnlistAnalyzer()
	var conns1, conns2 []connlist.Peer2PeerConnection
	var err error
	if conns1, err = caAnalyzer.ConnlistFromDirPath(dirPath1); err != nil {
		return nil, err
	}
	if conns2, err = caAnalyzer.ConnlistFromDirPath(dirPath2); err != nil {
		return nil, err
	}

	// get disjoint ip-blocks from both configs
	// TODO: avoid duplications of ip-blocks
	ipPeers1, ipPeers2 := getIPblocksFromConnList(conns1), getIPblocksFromConnList(conns2)
	disjointPeerIPMap, err := eval.DisjointPeerIPMap(ipPeers1, ipPeers2)
	if err != nil {
		return nil, err
	}

	// refine conns1,conns2 based on common disjoint ip-blocks
	conns1Refined, err := connlist.RefineConnListByDisjointPeers(conns1, disjointPeerIPMap)
	if err != nil {
		return nil, err
	}
	conns2Refined, err := connlist.RefineConnListByDisjointPeers(conns2, disjointPeerIPMap)
	if err != nil {
		return nil, err
	}

	// get the diff w.r.t refined sets of connectivity
	return diffConnectionsLists(conns1Refined, conns2Refined)
}

func getIPblocksFromConnList(conns []connlist.Peer2PeerConnection) []eval.Peer {
	peersMap := map[string]eval.Peer{}
	for _, p2p := range conns {
		if p2p.Src().IsPeerIPType() {
			peersMap[p2p.Src().String()] = p2p.Src()
		}
		if p2p.Dst().IsPeerIPType() {
			peersMap[p2p.Dst().String()] = p2p.Dst()
		}
	}
	res := make([]eval.Peer, len(peersMap))
	i := 0
	for _, p := range peersMap {
		res[i] = p
		i += 1
	}
	return res
}

func getKeyFromP2PConn(c connlist.Peer2PeerConnection) string {
	src := c.Src()
	dst := c.Dst()
	return src.String() + ";" + dst.String()
}

type ConnsPair struct {
	firstConn  connlist.Peer2PeerConnection
	secondConn connlist.Peer2PeerConnection
}

func (c *ConnsPair) update(isFirst bool, conn connlist.Peer2PeerConnection) {
	if isFirst {
		c.firstConn = conn
	} else {
		c.secondConn = conn
	}
}

type diffMap map[string]*ConnsPair

func (d diffMap) update(key string, isFirst bool, c connlist.Peer2PeerConnection) {
	if _, ok := d[key]; !ok {
		d[key] = &ConnsPair{}
	}
	d[key].update(isFirst, c)
}

// TODO: should modify the keys for ip-blocks, should work with disjoint ip-blocks from both results .
func diffConnectionsLists(conns1, conns2 []connlist.Peer2PeerConnection) (ConnectivityDiff, error) {
	// convert to a map from src-dst full name, to its connections pair (conns1, conns2)
	diffsMap := diffMap{}
	for _, c := range conns1 {
		diffsMap.update(getKeyFromP2PConn(c), true, c)
	}
	for _, c := range conns2 {
		diffsMap.update(getKeyFromP2PConn(c), false, c)
	}
	res := &connectivityDiff{
		removedConns: []connlist.Peer2PeerConnection{},
		addedConns:   []connlist.Peer2PeerConnection{},
		changedConns: []*ConnsPair{},
	}
	for _, d := range diffsMap {
		switch {
		case d.firstConn != nil && d.secondConn != nil:
			if !equalConns(d.firstConn, d.secondConn) {
				res.changedConns = append(res.changedConns, d)
			}
		case d.firstConn != nil:
			res.removedConns = append(res.removedConns, d.firstConn)
		case d.secondConn != nil:
			res.addedConns = append(res.addedConns, d.secondConn)
		default:
			continue
		}
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
	removedConns []connlist.Peer2PeerConnection
	addedConns   []connlist.Peer2PeerConnection
	changedConns []*ConnsPair
}

func (c *connectivityDiff) RemovedConnections() []connlist.Peer2PeerConnection {
	return c.removedConns
}

func (c *connectivityDiff) AddedConnections() []connlist.Peer2PeerConnection {
	return c.addedConns
}

func (c *connectivityDiff) ChangedConnections() []*ConnsPair {
	return c.changedConns
}

func (c *connectivityDiff) String() (string, error) {
	// currently only txt output is enabled, later add switch on output format
	return c.writeTxtDiffOutput()
}

// ConnectivityDiff captures differences in terms of connectivity between two input resource sets
type ConnectivityDiff interface {
	RemovedConnections() []connlist.Peer2PeerConnection // only first conn exists between peers
	AddedConnections() []connlist.Peer2PeerConnection   // only second conn exists between peers
	ChangedConnections() []*ConnsPair                   // both first & second conn exists between peers
	String() (string, error)                            // str summary of the connectivity diff
}

/***********************************************************************************************/
// writing outputs

const (
	// txt output header
	changedHeader = "Connectivity diff:"
	noConns       = "No Connections"
)

func (c *connectivityDiff) writeTxtDiffOutput() (string, error) {
	res := make([]string, 0)
	res = append(res, changedHeader)
	changedLines := c.writeChangedCategory()
	res = append(res, changedLines...)
	addedLines := c.writeAddedCategory()
	res = append(res, addedLines...)
	removedLines := c.writeRemovedCategory()
	res = append(res, removedLines...)

	return strings.Join(res, fmt.Sprintln("")), nil
}

func singleDiffTxtLine(srcName, dstName, conn1Str, conn2Str string) string {
	return fmt.Sprintf("source: %s, destination: %s, dir1:  %s, dir2: %s", srcName, dstName, conn1Str, conn2Str)
}

func (c *connectivityDiff) writeAddedCategory() []string {
	res := make([]string, 0)
	for _, p2pConn := range c.addedConns {
		res = append(res, singleDiffTxtLine(p2pConn.Src().String(), p2pConn.Dst().String(), noConns, connlist.GetProtocolsAndPortsStr(p2pConn)))
	}
	sort.Strings(res)
	return res
}

func (c *connectivityDiff) writeRemovedCategory() []string {
	res := make([]string, 0)
	for _, p2pConn := range c.removedConns {
		res = append(res, singleDiffTxtLine(p2pConn.Src().String(), p2pConn.Dst().String(), connlist.GetProtocolsAndPortsStr(p2pConn), noConns))
	}
	sort.Strings(res)
	return res
}

func (c *connectivityDiff) writeChangedCategory() []string {
	res := make([]string, 0)
	for _, pair := range c.changedConns {
		res = append(res, singleDiffTxtLine(pair.firstConn.Src().String(), pair.firstConn.Dst().String(),
			connlist.GetProtocolsAndPortsStr(pair.firstConn), connlist.GetProtocolsAndPortsStr(pair.secondConn)))
	}
	sort.Strings(res)
	return res
}
