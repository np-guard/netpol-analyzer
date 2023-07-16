package diff

import (
	"path/filepath"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/connlist"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/logger"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/scan"
)

type DiffAnalyzer struct {
	logger      logger.Logger
	stopOnError bool
	//errors        []ConnlistError
	walkFn  scan.WalkFunction
	scanner *scan.ResourcesScanner
	//focusWorkload string
	//outputFormat  string
}

func NewDiffAnalyzer() *DiffAnalyzer {
	// object with default behavior options
	da := &DiffAnalyzer{
		logger:      logger.NewDefaultLogger(),
		stopOnError: false,
		//errors:       []ConnlistError{},
		walkFn: filepath.WalkDir,
		//outputFormat: DefaultFormat,
	}
	/*for _, o := range options {
		o(ca)
	}*/
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

	return diffConnectionsLists(conns1, conns2)
}

func getKeyFromP2PConn(c connlist.Peer2PeerConnection) string {
	src := c.Src()
	dst := c.Dst()
	return src.String() + ";" + dst.String()
}

type connsPair struct {
	firstConn  connlist.Peer2PeerConnection
	secondConn connlist.Peer2PeerConnection
}

func (c *connsPair) update(isFirst bool, conn connlist.Peer2PeerConnection) {
	if isFirst {
		c.firstConn = conn
	} else {
		c.secondConn = conn
	}
}

type diffMap map[string]*connsPair

func (d diffMap) update(key string, isFirst bool, c connlist.Peer2PeerConnection) {
	if _, ok := d[key]; !ok {
		d[key] = &connsPair{}
	}
	d[key].update(isFirst, c)
}

// TODO: should modify the keys for ip-blocks, should work with disjoint ip-blocks from both results .
func diffConnectionsLists(conns1, conns2 []connlist.Peer2PeerConnection) (ConnectivityDiff, error) {
	// convert to a map from src-dst full name, to its connections pair (conns1, conns2)
	diffMap := diffMap{}
	for _, c := range conns1 {
		diffMap.update(getKeyFromP2PConn(c), true, c)
	}
	for _, c := range conns2 {
		diffMap.update(getKeyFromP2PConn(c), false, c)
	}
	res := &connectivityDiff{
		removedConns: []connlist.Peer2PeerConnection{},
		addedConns:   []connlist.Peer2PeerConnection{},
		changedConns: []*connsPair{},
	}
	for _, d := range diffMap {
		if d.firstConn != nil && d.secondConn != nil {
			res.changedConns = append(res.changedConns, d)
		} else if d.firstConn != nil {
			res.removedConns = append(res.removedConns, d.firstConn)
		} else if d.secondConn != nil {
			res.addedConns = append(res.addedConns, d.secondConn)
		}
	}

	return res, nil
}

type connectivityDiff struct {
	removedConns []connlist.Peer2PeerConnection
	addedConns   []connlist.Peer2PeerConnection
	changedConns []*connsPair
}

func (c *connectivityDiff) RemovedConnections() []connlist.Peer2PeerConnection {
	return c.removedConns
}

func (c *connectivityDiff) AddedConnections() []connlist.Peer2PeerConnection {
	return c.addedConns
}

func (c *connectivityDiff) ChangedConnections() []*connsPair {
	return c.changedConns
}

func (c *connectivityDiff) String() string {
	return ""
}

type ConnectivityDiff interface {
	RemovedConnections() []connlist.Peer2PeerConnection // only first conn exists between peers
	AddedConnections() []connlist.Peer2PeerConnection   // only second conn exists between peers
	ChangedConnections() []*connsPair                   // both first & second conn exists between peers
	String() string                                     // str summary of the connectivity diff
}
