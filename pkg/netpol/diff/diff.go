/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// The diff package of netpol-analyzer allows producing a k8s connectivity semantic-diff report based on several resources:
// k8s NetworkPolicy, k8s Ingress, openshift Route
// It lists the set of changed/removed/added connections between pair of peers (k8s workloads or ip-blocks).
// The resources can be extracted from two directories containing YAML manifests.
// For more information, see https://github.com/np-guard/netpol-analyzer.
package diff

import (
	"errors"
	"fmt"
	"os"
	"strings"

	v1 "k8s.io/api/core/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/cli-runtime/pkg/resource"

	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
	"github.com/np-guard/netpol-analyzer/pkg/internal/output"
	"github.com/np-guard/netpol-analyzer/pkg/logger"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/fsscanner"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/parser"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/connlist"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// Diff Analyzer funcs:

// ConnDiffFromResourceInfos returns the connectivity diffs from two lists of resource.Info objects,
// representing two versions of manifest sets to compare
func (da *DiffAnalyzer) ConnDiffFromResourceInfos(infos1, infos2 []*resource.Info) (ConnectivityDiff, error) {
	// connectivity analysis for first dir
	// TODO: should add input arg dirPath to this API func? so that log msgs can specify the dir, rather then just "ref1"/"ref2"
	conns1, workloads1, shouldStop, cDiff, errVal := da.getConnlistAnalysis(infos1, true, "")
	if shouldStop {
		return cDiff, errVal
	}

	// connectivity analysis for second dir
	conns2, workloads2, shouldStop, cDiff, errVal := da.getConnlistAnalysis(infos2, false, "")
	if shouldStop {
		return cDiff, errVal
	}

	// the actual diff analysis
	return da.computeDiffFromConnlistResults(conns1, conns2, workloads1, workloads2)
}

// ConnDiffFromDirPaths returns the connectivity diffs from two dir paths containing k8s resources,
// representing two versions of manifest sets to compare
func (da *DiffAnalyzer) ConnDiffFromDirPaths(dirPath1, dirPath2 string) (ConnectivityDiff, error) {
	// attempt to read manifests from both dirs
	infos1, errs1 := fsscanner.GetResourceInfosFromDirPath([]string{dirPath1}, true, da.stopOnError)
	infos2, errs2 := fsscanner.GetResourceInfosFromDirPath([]string{dirPath2}, true, da.stopOnError)

	if len(errs1) > 0 || len(errs2) > 0 {
		if (len(infos1) == 0 && len(infos2) == 0) || da.stopOnError || !doBothInputDirsExist(dirPath1, dirPath2) {
			err := utilerrors.NewAggregate(append(errs1, errs2...))
			dirPath := dirPath1
			if len(errs1) == 0 {
				dirPath = dirPath2
			}
			da.logger.Errorf(err, netpolerrors.ErrGettingResInfoFromDir+"s %s/%s ", da.ref1Name, da.ref2Name)
			da.errors = append(da.errors, parser.FailedReadingFile(dirPath, err))
			return nil, err // return as fatal error if both infos-lists are empty, or if stopOnError is on,
			// or if at least one input dir does not exist
		}

		// split err if it's an aggregated error to a list of separate errors
		for _, err := range errs1 {
			da.logger.Errorf(err, da.errPrefixSpecifyRefName(true)+netpolerrors.FailedReadingFileErrorStr) // print to log the error from builder
			da.errors = append(da.errors, parser.FailedReadingFile(dirPath1, err))
			// add the error from builder to accumulated errors
		}
		for _, err := range errs2 {
			da.logger.Errorf(err, da.errPrefixSpecifyRefName(false)+netpolerrors.FailedReadingFileErrorStr) // print to log the error from builder
			da.errors = append(da.errors, parser.FailedReadingFile(dirPath2, err))
			// add the error from builder to accumulated errors
		}
	}
	return da.ConnDiffFromResourceInfos(infos1, infos2)
}

func doBothInputDirsExist(dirPath1, dirPath2 string) bool {
	return dirExists(dirPath1) && dirExists(dirPath2)
}

func dirExists(dirPath string) bool {
	if _, err := os.Stat(dirPath); err != nil {
		// TODO: should any err != nil for os.Stat be considered as error to stop the analysis?
		// instead of checking os.IsNotExist specifically on err
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// computeDiffFromConnlistResults returns the ConnectivityDiff for the input connectivity results of each dir
func (da *DiffAnalyzer) computeDiffFromConnlistResults(
	conns1, conns2 []connlist.Peer2PeerConnection,
	workloads1, workloads2 []connlist.Peer,
) (ConnectivityDiff, error) {
	workloadsNames1, workloadsNames2 := getPeersNamesFromPeersList(workloads1), getPeersNamesFromPeersList(workloads2)

	// get disjoint src and dst ip-blocks from both configs
	srcIPPeers1, dstIPPeers1 := getIPblocksFromConnList(conns1)
	srcIPPeers2, dstIPPeers2 := getIPblocksFromConnList(conns2)
	srcDisjointPeerIPMap, err := eval.DisjointPeerIPMap(srcIPPeers1, srcIPPeers2)
	if err != nil {
		da.errors = append(da.errors, newHandlingIPpeersError(err))
		return nil, err
	}
	dstDisjointPeerIPMap, err := eval.DisjointPeerIPMap(dstIPPeers1, dstIPPeers2)
	if err != nil {
		da.errors = append(da.errors, newHandlingIPpeersError(err))
		return nil, err
	}

	// refine conns1,conns2 based on common disjoint ip-blocks
	conns1Refined, err := connlist.RefineConnListByDisjointPeers(conns1, srcDisjointPeerIPMap, dstDisjointPeerIPMap)
	if err != nil {
		da.errors = append(da.errors, newHandlingIPpeersError(err))
		return nil, err
	}
	conns2Refined, err := connlist.RefineConnListByDisjointPeers(conns2, srcDisjointPeerIPMap, dstDisjointPeerIPMap)
	if err != nil {
		da.errors = append(da.errors, newHandlingIPpeersError(err))
		return nil, err
	}

	// get the diff w.r.t refined sets of connectivity
	return diffConnectionsLists(conns1Refined, conns2Refined, workloadsNames1, workloadsNames2)
}

// getConnlistAnalysis calls ConnlistAnalyzer to analyze connectivity from input resource.Info objects.
// It appends to da.errors the errors/warnings returned from ConnlistAnalyzer
// It returns the connectivity analysis results ([]connlist.Peer2PeerConnection ,[]connlist.Peer )
// It also checks if the diff-analysis should stop due to fatal error, or severe err with stopOnErr flag
// Thus, it returns the additional set of values (bool, ConnectivityDiff, error), where the bool flag is
// true if the analysis should stop. The pair (ConnectivityDiff, error) are the values to be returned from
// the main function, if the analysis should stop.
func (da *DiffAnalyzer) getConnlistAnalysis(
	infos []*resource.Info,
	isRef1 bool,
	dirPath string) (
	[]connlist.Peer2PeerConnection,
	[]connlist.Peer,
	bool,
	ConnectivityDiff,
	error) {
	// get a new ConnlistAnalyzer with muted errs/warns
	connlistaAnalyzer := connlist.NewConnlistAnalyzer(da.determineConnlistAnalyzerOptions()...)
	conns, workloads, err := connlistaAnalyzer.ConnlistFromResourceInfos(infos)

	// append all fatal/severe errors and warnings returned by connlistaAnalyzer
	errPrefix := da.errPrefixSpecifyRefName(isRef1)
	for _, e := range connlistaAnalyzer.Errors() {
		// wrap err/warn with new err type that includes context of ref1/ref2
		daErr := newConnectivityAnalysisError(e.Error(), errPrefix, dirPath, e.IsSevere(), e.IsFatal())
		da.errors = append(da.errors, daErr)
		logErrOrWarning(daErr, da.logger)
	}
	if err != nil {
		// assuming that the fatal error should exist in the errors array from connlistaAnalyzer.Errors()
		// check it exists, if not, append a new fatal err to the da.errors array
		if da.hasFatalError() == nil {
			// append the fatal error (indicates an issue in connlist analyzer, that did not append this err as expected)
			da.errors = append(da.errors, newConnectivityAnalysisError(err, errPrefix, dirPath, false, true))
		}
	}

	shouldStop := false
	var errVal error
	cDiff := &connectivityDiff{}
	// stopProcessing checks if there is a fatal err, or severe err with stopOnErr flag
	if da.stopProcessing() {
		shouldStop = true
		if err := da.hasFatalError(); err != nil {
			// a fatal err should be returned and not only be kept in the da.errors array
			errVal = err
			cDiff = nil
		}
	}

	return conns, workloads, shouldStop, cDiff, errVal
}

// return a []ConnlistAnalyzerOption with mute errs/warns, so that logging of err/wanr is not duplicated, and
// added to log only by getConnlistAnalysis function, which adds the context of ref1/ref2
func (da *DiffAnalyzer) determineConnlistAnalyzerOptions() []connlist.ConnlistAnalyzerOption {
	if da.stopOnError {
		return []connlist.ConnlistAnalyzerOption{connlist.WithMuteErrsAndWarns(), connlist.WithLogger(da.logger), connlist.WithStopOnError()}
	}
	return []connlist.ConnlistAnalyzerOption{connlist.WithMuteErrsAndWarns(), connlist.WithLogger(da.logger)}
}

func (da *DiffAnalyzer) errPrefixSpecifyRefName(isRef1 bool) string {
	if isRef1 {
		return getErrPrefix(da.ref1Name)
	}
	return getErrPrefix(da.ref2Name)
}

func getErrPrefix(location string) string {
	return fmt.Sprintf("at %s: ", location)
}

// loops the errors that were returned from the connlistAnalyzer
// (as only connlistAnalyzer.Errors() may contain severe errors; all other DiffAnalyzer errors are fatal),
// returns true if has fatal error or severe error with flag stopOnError
func (da *DiffAnalyzer) stopProcessing() bool {
	for _, e := range da.errors {
		if e.IsFatal() || da.stopOnError && e.IsSevere() {
			return true
		}
	}
	return false
}

func (da *DiffAnalyzer) hasFatalError() error {
	for idx := range da.errors {
		if da.errors[idx].IsFatal() {
			return da.errors[idx].Error()
		}
	}
	return nil
}

func logErrOrWarning(d DiffError, l logger.Logger) {
	if d.IsSevere() || d.IsFatal() {
		l.Errorf(d.Error(), "")
	} else {
		l.Warnf(d.Error().Error())
	}
}

// create set from peers-strings;
// peers is a list of workloads from the manifests
func getPeersNamesFromPeersList(peers []connlist.Peer) map[string]bool {
	peersSet := make(map[string]bool, 0)
	for _, peer := range peers {
		// eliminating "[udn]" label from peer strings so if the udn was added/removed, peers are not considered different
		peerStr := strings.ReplaceAll(peer.String(), common.UDNLabel, "")
		peersSet[peerStr] = true
	}
	return peersSet
}

// getIPblocksFromConnList returns the list of peers of IP type from Peer2PeerConnection slice
func getIPblocksFromConnList(conns []connlist.Peer2PeerConnection) (srcPeers, dstPeers []eval.Peer) {
	srcPeersMap := map[string]eval.Peer{}
	dstPeersMap := map[string]eval.Peer{}
	for _, p2p := range conns {
		if p2p.Src().IsPeerIPType() {
			srcPeersMap[p2p.Src().String()] = p2p.Src()
		}
		if p2p.Dst().IsPeerIPType() {
			dstPeersMap[p2p.Dst().String()] = p2p.Dst()
		}
	}
	return getPeersSliceFromSet(srcPeersMap), getPeersSliceFromSet(dstPeersMap)
}

// getPeersSliceFromSet returns slice from the map keys
func getPeersSliceFromSet(peersMap map[string]eval.Peer) []eval.Peer {
	res := make([]eval.Peer, len(peersMap))
	i := 0
	for _, p := range peersMap {
		res[i] = p
		i += 1
	}
	return res
}

// ValidDiffFormats are the supported formats for output generation of the diff command
var ValidDiffFormats = []string{output.TextFormat, output.CSVFormat, output.MDFormat, output.DOTFormat, output.SVGFormat}

// ConnectivityDiffToString returns a string of connections diff from connectivityDiff object in the required output format
func (da *DiffAnalyzer) ConnectivityDiffToString(connectivityDiff ConnectivityDiff) (string, error) {
	if connectivityDiff.IsEmpty() {
		da.logger.Infof("No connections diff")
		return "", nil
	}
	da.logger.Infof("Found connections diffs")
	diffFormatter, err := getFormatter(da.outputFormat, da.ref1Name, da.ref2Name)
	if err != nil {
		da.errors = append(da.errors, newResultFormattingError(err))
		return "", err
	}
	out, err := diffFormatter.writeDiffOutput(connectivityDiff)
	if err != nil {
		da.errors = append(da.errors, newResultFormattingError(err))
		return "", err
	}
	return out, nil
}

// returns the relevant formatter for the analyzer's outputFormat
func getFormatter(format, ref1Name, ref2Name string) (diffFormatter, error) {
	if err := output.ValidateOutputFormat(format, ValidDiffFormats); err != nil {
		return nil, err
	}
	switch format {
	case output.TextFormat:
		return &diffFormatText{ref1: ref1Name, ref2: ref2Name}, nil
	case output.CSVFormat:
		return &diffFormatCSV{ref1: ref1Name, ref2: ref2Name}, nil
	case output.MDFormat:
		return &diffFormatMD{ref1: ref1Name, ref2: ref2Name}, nil
	case output.DOTFormat:
		return &diffFormatDOT{ref1: ref1Name, ref2: ref2Name}, nil
	case output.SVGFormat:
		return &diffFormatSVG{ref1: ref1Name, ref2: ref2Name}, nil
	default:
		return &diffFormatText{ref1: ref1Name, ref2: ref2Name}, nil
	}
}

////////////////////////////////////////////
// Diff Conns List Compute:

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
	if (!src.IsPeerIPType() && !isIngressControllerPeer(src)) && !peersSet[src.String()] {
		c.newOrLostSrc = true
	}
	if (!dst.IsPeerIPType() && !isIngressControllerPeer(dst)) && !peersSet[dst.String()] {
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
	// eliminating "[udn]" label from src/dst strings so if the udn was added/removed, peers are not considered different
	srcStr := strings.ReplaceAll(c.Src().String(), common.UDNLabel, "")
	dstStr := strings.ReplaceAll(c.Dst().String(), common.UDNLabel, "")
	return srcStr + keyElemSep + dstStr
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
