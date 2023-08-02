package diff

import (
	"errors"
	"path/filepath"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/common"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/connlist"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/logger"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/scan"
)

type DiffAnalyzer struct {
	logger       logger.Logger
	stopOnError  bool
	errors       []DiffError
	walkFn       scan.WalkFunction
	scanner      *scan.ResourcesScanner
	outputFormat string
}

var ValidDiffFormats = []string{common.TextFormat, common.CSVFormat, common.MDFormat}

// DiffAnalyzerOption is the type for specifying options for DiffAnalyzer,
// using Golang's Options Pattern (https://golang.cafe/blog/golang-functional-options-pattern.html).
type DiffAnalyzerOption func(*DiffAnalyzer)

// WithLogger is a functional option which sets the logger for a DiffAnalyzer to use.
// The provided logger must conform with the package's Logger interface.
func WithLogger(l logger.Logger) DiffAnalyzerOption {
	return func(c *DiffAnalyzer) {
		c.logger = l
	}
}

// WithOutputFormat is a functional option, allowing user to choose the output format txt/csv/md.
func WithOutputFormat(outputFormat string) DiffAnalyzerOption {
	return func(d *DiffAnalyzer) {
		d.outputFormat = outputFormat
	}
}

// WithStopOnError is a functional option which directs DiffAnalyzer to stop any processing after the
// first severe error.
func WithStopOnError() DiffAnalyzerOption {
	return func(d *DiffAnalyzer) {
		d.stopOnError = true
	}
}

func NewDiffAnalyzer(options ...DiffAnalyzerOption) *DiffAnalyzer {
	// object with default behavior options
	da := &DiffAnalyzer{
		logger:       logger.NewDefaultLogger(),
		stopOnError:  false,
		errors:       []DiffError{},
		walkFn:       filepath.WalkDir,
		outputFormat: common.DefaultFormat,
	}
	for _, o := range options {
		o(da)
	}
	da.scanner = scan.NewResourcesScanner(da.logger, da.stopOnError, da.walkFn)
	return da
}

// Errors returns a slice of DiffError with all warnings and errors encountered during processing.
func (da *DiffAnalyzer) Errors() []DiffError {
	return da.errors
}

// ConnDiffFromDirPaths returns the connectivity diffs from two dir paths containing k8s resources
func (da *DiffAnalyzer) ConnDiffFromDirPaths(dirPath1, dirPath2 string) (ConnectivityDiff, error) {
	var caAnalyzer *connlist.ConnlistAnalyzer
	if da.stopOnError {
		caAnalyzer = connlist.NewConnlistAnalyzer(connlist.WithLogger(da.logger), connlist.WithWalkFn(da.walkFn),
			connlist.WithStopOnError())
	} else {
		caAnalyzer = connlist.NewConnlistAnalyzer(connlist.WithLogger(da.logger), connlist.WithWalkFn(da.walkFn))
	}
	var conns1, conns2 []connlist.Peer2PeerConnection
	var err error
	if conns1, err = caAnalyzer.ConnlistFromDirPath(dirPath1); err != nil {
		da.errors = append(da.errors, newConnectionsAnalyzingError(err, true, false))
		return nil, err
	}
	if conns2, err = caAnalyzer.ConnlistFromDirPath(dirPath2); err != nil {
		da.errors = append(da.errors, newConnectionsAnalyzingError(err, true, false))
		return nil, err
	}
	// appending connlist warnings and severe errors to diff_errors
	for _, e := range caAnalyzer.Errors() {
		da.errors = append(da.errors, e)
	}

	// get disjoint ip-blocks from both configs
	// TODO: avoid duplications of ip-blocks
	ipPeers1, ipPeers2 := getIPblocksFromConnList(conns1), getIPblocksFromConnList(conns2)
	disjointPeerIPMap, err := eval.DisjointPeerIPMap(ipPeers1, ipPeers2)
	if err != nil {
		da.errors = append(da.errors, newHandlingIPpeersError(err))
		return nil, err
	}

	// refine conns1,conns2 based on common disjoint ip-blocks
	conns1Refined, err := connlist.RefineConnListByDisjointPeers(conns1, disjointPeerIPMap)
	if err != nil {
		da.errors = append(da.errors, newHandlingIPpeersError(err))
		return nil, err
	}
	conns2Refined, err := connlist.RefineConnListByDisjointPeers(conns2, disjointPeerIPMap)
	if err != nil {
		da.errors = append(da.errors, newHandlingIPpeersError(err))
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

// ConnsPair pairs of Peer2PeerConnection from two dir paths
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

// ValidateDiffOutputFormat validate the value of the diff output format
func ValidateDiffOutputFormat(format string) error {
	for _, formatName := range ValidDiffFormats {
		if format == formatName {
			return nil
		}
	}
	return errors.New(format + " output format is not supported.")
}

// ConnectivityDiffToString returns a string of connections diff from connectivityDiff object in the required output format
func (da *DiffAnalyzer) ConnectivityDiffToString(connectivityDiff ConnectivityDiff) (string, error) {
	if connectivityDiff.isEmpty() {
		da.logger.Infof("No connections diff")
		return "", nil
	}
	da.logger.Infof("Found connections diffs")
	diffFormatter, err := getFormatter(da.outputFormat)
	if err != nil {
		da.errors = append(da.errors, newResultFormattingError(err))
		return "", err
	}
	output, err := diffFormatter.writeDiffOutput(connectivityDiff)
	if err != nil {
		da.errors = append(da.errors, newResultFormattingError(err))
		return "", err
	}
	return output, nil
}

// returns the relevant formatter for the analyzer's outputFormat
func getFormatter(format string) (diffFormatter, error) {
	if err := ValidateDiffOutputFormat(format); err != nil {
		return nil, err
	}
	switch format {
	case common.TextFormat:
		return &diffFormatText{}, nil
	case common.CSVFormat:
		return &diffFormatCSV{}, nil
	case common.MDFormat:
		return &diffFormatMD{}, nil
	default:
		return &diffFormatText{}, nil
	}
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

func (c *connectivityDiff) isEmpty() bool {
	return len(c.removedConns) == 0 && len(c.addedConns) == 0 && len(c.changedConns) == 0
}

// ConnectivityDiff captures differences in terms of connectivity between two input resource sets
type ConnectivityDiff interface {
	RemovedConnections() []connlist.Peer2PeerConnection // only first conn exists between peers
	AddedConnections() []connlist.Peer2PeerConnection   // only second conn exists between peers
	ChangedConnections() []*ConnsPair                   // both first & second conn exists between peers
	isEmpty() bool
}
