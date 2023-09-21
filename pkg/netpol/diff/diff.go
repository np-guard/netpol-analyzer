// The diff package of netpol-analyzer allows producing a k8s connectivity semantic-diff report based on several resources:
// k8s NetworkPolicy, k8s Ingress, openshift Route
// It lists the set of changed/removed/added connections between pair of peers (k8s workloads or ip-blocks).
// The resources can be extracted from two directories containing YAML manifests.
// For more information, see https://github.com/np-guard/netpol-analyzer.
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

// A DiffAnalyzer provides API to recursively scan two directories for Kubernetes resources including network policies,
// and get the difference of permitted connectivity between the workloads of the K8s application managed in theses directories.
type DiffAnalyzer struct {
	logger               logger.Logger
	stopOnError          bool
	errors               []DiffError
	walkFn               scan.WalkFunction
	outputFormat         string
	includeJSONManifests bool
}

// ValidDiffFormats are the supported formats for output generation of the diff command
var ValidDiffFormats = []string{common.TextFormat, common.CSVFormat, common.MDFormat, common.DOTFormat}

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

// WithIncludeJSONManifests is a functional option which directs ConnlistAnalyzer to include JSON manifests in the analysis
func WithIncludeJSONManifests() DiffAnalyzerOption {
	return func(d *DiffAnalyzer) {
		d.includeJSONManifests = true
	}
}

// NewDiffAnalyzer creates a new instance of DiffAnalyzer, and applies the provided functional options.
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
	return da
}

// Errors returns a slice of DiffError with all warnings and errors encountered during processing.
func (da *DiffAnalyzer) Errors() []DiffError {
	return da.errors
}

// return true if has fatal error or severe with flag stopOnError
func (da *DiffAnalyzer) stopProcessing() bool {
	for idx := range da.errors {
		if da.errors[idx].IsFatal() || da.stopOnError && da.errors[idx].IsSevere() {
			return true
		}
	}
	return false
}

// appending connlist warnings and severe errors to diff_errors
func (da *DiffAnalyzer) appendConnlistErrorsToDiffErrors(caErrors []connlist.ConnlistError) {
	for _, e := range caErrors {
		// interfaces ConnlistError and DiffError has same functionality, so we can append to each other implicitly
		da.errors = append(da.errors, e)
	}
}

func (da *DiffAnalyzer) determineConnlistAnalyzerOptionsForDiffAnalysis() []connlist.ConnlistAnalyzerOption {
	res := []connlist.ConnlistAnalyzerOption{connlist.WithLogger(da.logger), connlist.WithWalkFn(da.walkFn)}
	if da.includeJSONManifests {
		res = append(res, connlist.WithIncludeJSONManifests())
	}
	if da.stopOnError {
		res = append(res, connlist.WithStopOnError())
	}
	return res
}

// ConnDiffFromDirPaths returns the connectivity diffs from two dir paths containing k8s resources
func (da *DiffAnalyzer) ConnDiffFromDirPaths(dirPath1, dirPath2 string) (ConnectivityDiff, error) {
	caAnalyzer := connlist.NewConnlistAnalyzer(da.determineConnlistAnalyzerOptionsForDiffAnalysis()...)
	var conns1, conns2 []connlist.Peer2PeerConnection
	var workloads1, workloads2 []connlist.Peer
	var workloadsNames1, workloadsNames2 map[string]bool
	var err error
	if conns1, workloads1, err = caAnalyzer.ConnlistFromDirPath(dirPath1); err != nil {
		da.errors = append(da.errors, newConnectionsAnalyzingError(err, true, false))
		return nil, err
	}
	da.appendConnlistErrorsToDiffErrors(caAnalyzer.Errors())
	if da.stopProcessing() {
		return &connectivityDiff{}, nil
	}
	if conns2, workloads2, err = caAnalyzer.ConnlistFromDirPath(dirPath2); err != nil {
		da.errors = append(da.errors, newConnectionsAnalyzingError(err, true, false))
		return nil, err
	}
	da.appendConnlistErrorsToDiffErrors(caAnalyzer.Errors())
	if da.stopProcessing() {
		return &connectivityDiff{}, nil
	}
	workloadsNames1, workloadsNames2 = getPeersNamesFromPeersList(workloads1), getPeersNamesFromPeersList(workloads2)

	// get disjoint ip-blocks from both configs
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
	return diffConnectionsLists(conns1Refined, conns2Refined, workloadsNames1, workloadsNames2)
}

// create set from peers-strings
func getPeersNamesFromPeersList(peers []connlist.Peer) map[string]bool {
	peersSet := make(map[string]bool, 0)
	for _, peer := range peers {
		if !peer.IsPeerIPType() {
			peersSet[peer.String()] = true
		}
	}
	return peersSet
}

// getIPblocksFromConnList returns the list of peers of IP type from Peer2PeerConnection slice
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

// getKeyFromP2PConn returns the form of `src;dst“ from Peer2PeerConnection object, to be used as key in diffMap
func getKeyFromP2PConn(c connlist.Peer2PeerConnection) string {
	src := c.Src()
	dst := c.Dst()
	return src.String() + keyElemSep + dst.String()
}

const (
	// diff types
	changedType    = "changed"
	removedType    = "removed"
	addedType      = "added"
	nonChangedType = "nonChanged"
)

// ConnsPair captures a pair of Peer2PeerConnection from two dir paths
// the src,dst of firstConn and secondConn are assumed to be the same
// with info on the diffType and if any of the peers is lost/new
// (exists only in one dir for cases of removed/added connections)
type ConnsPair struct {
	firstConn    connlist.Peer2PeerConnection
	secondConn   connlist.Peer2PeerConnection
	diffType     string
	newOrLostSrc bool
	newOrLostDst bool
}

// update func of ConnsPair obj, updates the pair with input Peer2PeerConnection, at first or second conn
func (c *ConnsPair) updateConn(isFirst bool, conn connlist.Peer2PeerConnection) {
	if isFirst {
		c.firstConn = conn
	} else {
		c.secondConn = conn
	}
}

// isSrcOrDstPeerIPType returns whether src (if checkSrc is true) or dst (if checkSrc is false) is of IP type
func (c *ConnsPair) isSrcOrDstPeerIPType(checkSrc bool) bool {
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

// helpers to check if a peer is ingress-controller (a peer created while ingress analysis)
const ingressControllerPodName = "{ingress-controller}"

func isIngressControllerPeer(peer eval.Peer) bool {
	return peer.String() == ingressControllerPodName
}

// updateNewOrLostFields updates ConnsPair's newOrLostSrc and newOrLostDst values
func (c *ConnsPair) updateNewOrLostFields(isFirst bool, peersSet map[string]bool) {
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
type diffMap map[string]*ConnsPair

// update func of diffMap, updates the map input key and Peer2PeerConnection, at first or second conn
func (d diffMap) update(key string, isFirst bool, c connlist.Peer2PeerConnection) {
	if _, ok := d[key]; !ok {
		d[key] = &ConnsPair{}
	}
	d[key].updateConn(isFirst, c)
}

// type mapListConnPairs is a map from key (src-or-dst)+conns1+conns2 to []ConnsPair (where dst-or-src is ip-block)
// it is used to group disjoint ip-blocks and merge overlapping/touching ip-blocks when possible
type mapListConnPairs map[string][]*ConnsPair

const keyElemSep = ";"

// addConnsPair is given ConnsPair with src or dst as ip-block, and updates mapListConnPairs
func (m mapListConnPairs) addConnsPair(c *ConnsPair, isSrcAnIP bool) error {
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
		m[newKey] = []*ConnsPair{}
	}
	m[newKey] = append(m[newKey], c)

	return nil
}

// getConnStringsFromConnsPair returns string representation of connections from the pair at ConnsPair
func getConnStringsFromConnsPair(c *ConnsPair) (conn1, conn2 string, err error) {
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
func getDstOrSrcFromConnsPair(c *ConnsPair, isDst bool) eval.Peer {
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
		removedConns:    []*ConnsPair{},
		addedConns:      []*ConnsPair{},
		changedConns:    []*ConnsPair{},
		nonChangedConns: []*ConnsPair{},
	}
	for _, d := range diffsMap {
		switch {
		case d.firstConn != nil && d.secondConn != nil:
			if !equalConns(d.firstConn, d.secondConn) {
				d.diffType = changedType
				d.newOrLostSrc, d.newOrLostDst = false, false
				res.changedConns = append(res.changedConns, d)
			} else { // equal - non changed
				d.diffType = nonChangedType
				d.newOrLostSrc, d.newOrLostDst = false, false
				res.nonChangedConns = append(res.nonChangedConns, d)
			}
		case d.firstConn != nil:
			// removed conn means both Src and Dst exist in peers1, just check if they are not in peers2 too
			d.diffType = removedType
			d.updateNewOrLostFields(true, peers2)
			res.removedConns = append(res.removedConns, d)
		case d.secondConn != nil:
			// added conns means Src and Dst are in peers2, check if they didn't exist in peers1 too
			d.diffType = addedType
			d.updateNewOrLostFields(false, peers1)
			res.addedConns = append(res.addedConns, d)
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
	if connectivityDiff.IsEmpty() {
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
	case common.DOTFormat:
		return &diffFormatDOT{}, nil
	default:
		return &diffFormatText{}, nil
	}
}

// connectivityDiff implements the ConnectivityDiff interface
type connectivityDiff struct {
	removedConns    []*ConnsPair
	addedConns      []*ConnsPair
	changedConns    []*ConnsPair
	nonChangedConns []*ConnsPair
}

func (c *connectivityDiff) RemovedConnections() []*ConnsPair {
	return c.removedConns
}

func (c *connectivityDiff) AddedConnections() []*ConnsPair {
	return c.addedConns
}

func (c *connectivityDiff) ChangedConnections() []*ConnsPair {
	return c.changedConns
}

func (c *connectivityDiff) IsEmpty() bool {
	return len(c.removedConns) == 0 && len(c.addedConns) == 0 && len(c.changedConns) == 0
}

func (c *connectivityDiff) NonChangedConnections() []*ConnsPair {
	return c.nonChangedConns
}

// ConnectivityDiff captures differences in terms of connectivity between two input resource sets
type ConnectivityDiff interface {
	RemovedConnections() []*ConnsPair    // only first conn exists between peers, plus indications if any of the peers removed
	AddedConnections() []*ConnsPair      // only second conn exists between peers, plus indications if any of the peers is new
	ChangedConnections() []*ConnsPair    // both first & second conn exists between peers
	IsEmpty() bool                       // indicates if no diff between connections, i.e. removed, added and changed connections are empty
	NonChangedConnections() []*ConnsPair // non changed conns, both first & second conn exists and equal between the peers
}
