package diff

import (
	"errors"
	"fmt"
	"os"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/cli-runtime/pkg/resource"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/common"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/connlist"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/logger"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/manifests/fsscanner"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/manifests/parser"
)

// A DiffAnalyzer provides API to recursively scan two directories for Kubernetes resources including network policies,
// and get the difference of permitted connectivity between the workloads of the K8s application managed in theses directories.
type DiffAnalyzer struct {
	logger       logger.Logger
	stopOnError  bool
	errors       []DiffError
	outputFormat string
	ref1Name     string
	ref2Name     string
}

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

// WithArgNames is a functional option that sets the names to be used for the two sets of analyzed resources
// (default is ref1,ref2) in the output reports and log messages.
func WithArgNames(ref1Name, ref2Name string) DiffAnalyzerOption {
	return func(d *DiffAnalyzer) {
		d.ref1Name = ref1Name
		d.ref2Name = ref2Name
	}
}

// Errors returns a slice of DiffError with all warnings and errors encountered during processing.
func (da *DiffAnalyzer) Errors() []DiffError {
	return da.errors
}

// NewDiffAnalyzer creates a new instance of DiffAnalyzer, and applies the provided functional options.
func NewDiffAnalyzer(options ...DiffAnalyzerOption) *DiffAnalyzer {
	// object with default behavior options
	da := &DiffAnalyzer{
		logger:       logger.NewDefaultLogger(),
		stopOnError:  false,
		errors:       []DiffError{},
		outputFormat: common.DefaultFormat,
		ref1Name:     "ref1",
		ref2Name:     "ref2",
	}
	for _, o := range options {
		o(da)
	}
	return da
}

// ValidDiffFormats are the supported formats for output generation of the diff command
var ValidDiffFormats = []string{common.TextFormat, common.CSVFormat, common.MDFormat, common.DOTFormat}

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
			da.logger.Errorf(err, "Error getting resourceInfos from dir paths %s/%s ", da.ref1Name, da.ref2Name)
			da.errors = append(da.errors, parser.FailedReadingFile(dirPath, err))
			return nil, err // return as fatal error if both infos-lists are empty, or if stopOnError is on,
			// or if at least one input dir does not exist
		}

		// split err if it's an aggregated error to a list of separate errors
		errReadingFile := "error reading file"
		for _, err := range errs1 {
			da.logger.Errorf(err, da.errPrefixSpecifyRefName(true)+errReadingFile) // print to log the error from builder
			da.errors = append(da.errors, parser.FailedReadingFile(dirPath1, err)) // add the error from builder to accumulated errors
		}
		for _, err := range errs2 {
			da.logger.Errorf(err, da.errPrefixSpecifyRefName(false)+errReadingFile) // print to log the error from builder
			da.errors = append(da.errors, parser.FailedReadingFile(dirPath2, err))  // add the error from builder to accumulated errors
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
	output, err := diffFormatter.writeDiffOutput(connectivityDiff)
	if err != nil {
		da.errors = append(da.errors, newResultFormattingError(err))
		return "", err
	}
	return output, nil
}

// returns the relevant formatter for the analyzer's outputFormat
func getFormatter(format, ref1Name, ref2Name string) (diffFormatter, error) {
	if err := ValidateDiffOutputFormat(format); err != nil {
		return nil, err
	}
	switch format {
	case common.TextFormat:
		return &diffFormatText{ref1: ref1Name, ref2: ref2Name}, nil
	case common.CSVFormat:
		return &diffFormatCSV{ref1: ref1Name, ref2: ref2Name}, nil
	case common.MDFormat:
		return &diffFormatMD{ref1: ref1Name, ref2: ref2Name}, nil
	case common.DOTFormat:
		return &diffFormatDOT{ref1: ref1Name, ref2: ref2Name}, nil
	default:
		return &diffFormatText{ref1: ref1Name, ref2: ref2Name}, nil
	}
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
