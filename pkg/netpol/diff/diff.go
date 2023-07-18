package diff

import (
	"path/filepath"
	"reflect"
	"strings"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/connlist"
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
	// todo : add optins
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
		changedConns: []*connsPair{},
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
	return firstConn.AllProtocolsAndPorts() == secondConn.AllProtocolsAndPorts() &&
		reflect.DeepEqual(firstConn.ProtocolsAndPorts(), secondConn.ProtocolsAndPorts())
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

func (c *connectivityDiff) String() (string, error) {
	// currently only txt output is enabled, later add switch on output format
	clAnalyzer := connlist.NewConnlistAnalyzer() // creates a ca with default output format (txt)
	return c.writeTxtDiffOutput(clAnalyzer)
}

type ConnectivityDiff interface {
	RemovedConnections() []connlist.Peer2PeerConnection // only first conn exists between peers
	AddedConnections() []connlist.Peer2PeerConnection   // only second conn exists between peers
	ChangedConnections() []*connsPair                   // both first & second conn exists between peers
	String() (string, error)                            // str summary of the connectivity diff
}

/***********************************************************************************************/
// writing outputs

const (
	// txt output headers
	removedHeader = "Lost Connections:"
	addedHeader   = "\nNew Connections:"
	changedHeader = "\nChanged Connections:"
	beforeHeader  = "**Connections Before:"
	afterHeader   = "**Connections After:"
)

func (c *connectivityDiff) writeTxtDiffOutput(ca *connlist.ConnlistAnalyzer) (string, error) {
	res := make([]string, 0)
	removedLines, err := writeRemovedorAddedCategory(removedHeader, c.removedConns, ca)
	if err != nil {
		return "", err
	}
	res = append(res, removedLines)
	addedLines, err := writeRemovedorAddedCategory(addedHeader, c.addedConns, ca)
	if err != nil {
		return "", err
	}
	res = append(res, addedLines)
	changedLines, err := writeChangedCategory(changedHeader, c.changedConns, ca)
	if err != nil {
		return "", err
	}
	res = append(res, changedLines)
	return strings.Join(res, connlist.GetNewLineChar()), nil
}

func writeRemovedorAddedCategory(categoryHeader string, conns []connlist.Peer2PeerConnection,
	ca *connlist.ConnlistAnalyzer) (string, error) {
	res := make([]string, 0)
	res = append(res, categoryHeader)
	categoryLines, err := ca.ConnectionsListToString(conns)
	if err != nil {
		return "", err
	}
	res = append(res, categoryLines)
	return strings.Join(res, connlist.GetNewLineChar()), nil
}

func writeChangedCategory(categoryHeader string, connsPairs []*connsPair,
	ca *connlist.ConnlistAnalyzer) (string, error) {
	res := make([]string, 0)
	res = append(res, categoryHeader)
	beforeConns := make([]connlist.Peer2PeerConnection, 0)
	afterConns := make([]connlist.Peer2PeerConnection, 0)
	for _, pair := range connsPairs {
		beforeConns = append(beforeConns, pair.firstConn)
		afterConns = append(afterConns, pair.secondConn)
	}
	beforeLines, err := ca.ConnectionsListToString(beforeConns)
	if err != nil {
		return "", err
	}
	if beforeLines != "" {
		res = append(res, beforeHeader, beforeLines)
	}

	afterLines, err := ca.ConnectionsListToString(afterConns)
	if err != nil {
		return "", err
	}
	if afterLines != "" {
		res = append(res, afterHeader, afterLines)
	}

	return strings.Join(res, connlist.GetNewLineChar()), nil
}
