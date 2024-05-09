// The connlist package of netpol-analyzer allows producing a k8s connectivity report based on several resources:
// k8s NetworkPolicy, k8s Ingress, openshift Route
// It lists the set of allowed connections between each pair of different peers (k8s workloads or ip-blocks).
// Connections between workload to itself are excluded from the output.
// Connectivity inferred from Ingress/Route resources is between {ingress-controller} to k8s workloads.
// The resources can be extracted from a directory containing YAML manifests, or from a k8s cluster.
// For more information, see https://github.com/np-guard/netpol-analyzer.
package connlist

import (
	"context"
	"errors"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	v1 "k8s.io/api/core/v1"

	"k8s.io/cli-runtime/pkg/resource"

	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
	"github.com/np-guard/netpol-analyzer/pkg/internal/output"
	"github.com/np-guard/netpol-analyzer/pkg/logger"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/fsscanner"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/parser"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/connlist/internal/ingressanalyzer"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"
)

// A ConnlistAnalyzer provides API to recursively scan a directory for Kubernetes resources including network policies,
// and get the list of permitted connectivity between the workloads of the K8s application managed in this directory.
type ConnlistAnalyzer struct {
	logger           logger.Logger
	stopOnError      bool
	errors           []ConnlistError
	focusWorkload    string
	exposureAnalysis bool
	exposureResult   []ExposedPeer
	outputFormat     string
	muteErrsAndWarns bool
}

// The new interface
// ConnlistFromResourceInfos returns the allowed-connections list from input slice of resource.Info objects,
// and the list of all workloads from the parsed resources
func (ca *ConnlistAnalyzer) ConnlistFromResourceInfos(info []*resource.Info) ([]Peer2PeerConnection, []Peer, error) {
	// convert resource.Info objects to k8s resources, filter irrelevant resources
	objs, fpErrs := parser.ResourceInfoListToK8sObjectsList(info, ca.logger, ca.muteErrsAndWarns)
	ca.copyFpErrs(fpErrs)
	if ca.stopProcessing() {
		if err := ca.hasFatalError(); err != nil {
			return nil, nil, err
		}
		return []Peer2PeerConnection{}, []Peer{}, nil
	}
	return ca.connslistFromParsedResources(objs)
}

func (ca *ConnlistAnalyzer) copyFpErrs(fpErrs []parser.FileProcessingError) {
	for i := range fpErrs {
		ca.errors = append(ca.errors, &fpErrs[i])
	}
}

// ConnlistFromDirPath returns the allowed connections list from dir path containing k8s resources,
// and list of all workloads from the parsed resources
func (ca *ConnlistAnalyzer) ConnlistFromDirPath(dirPath string) ([]Peer2PeerConnection, []Peer, error) {
	rList, errs := fsscanner.GetResourceInfosFromDirPath([]string{dirPath}, true, ca.stopOnError)
	// instead of parsing the builder's string error to decide on error type (warning/error/fatal-err)
	// return as fatal error if rList is empty or if stopOnError is on
	// otherwise try to analyze and return as accumulated error
	if errs != nil {
		// TODO: consider avoid logging this error because it is already printed to log by the builder
		if len(rList) == 0 || ca.stopOnError {
			err := utilerrors.NewAggregate(errs)
			ca.logger.Errorf(err, netpolerrors.ErrGettingResInfoFromDir)
			ca.errors = append(ca.errors, parser.FailedReadingFile(dirPath, err))
			return nil, nil, err // return as fatal error if rList is empty or if stopOnError is on
		}
		// split err if it's an aggregated error to a list of separate errors
		for _, err := range errs {
			ca.logger.Errorf(err, netpolerrors.FailedReadingFileErrorStr)         // print to log the error from builder
			ca.errors = append(ca.errors, parser.FailedReadingFile(dirPath, err)) // add the error from builder to accumulated errors
		}
	}
	return ca.ConnlistFromResourceInfos(rList)
}

// ValidFormats array of possible values of output format
var ValidFormats = []string{output.TextFormat, output.JSONFormat, output.DOTFormat,
	output.CSVFormat, output.MDFormat}

var ExposureValidFormats = []string{output.TextFormat, output.DOTFormat}

// ConnlistAnalyzerOption is the type for specifying options for ConnlistAnalyzer,
// using Golang's Options Pattern (https://golang.cafe/blog/golang-functional-options-pattern.html).
type ConnlistAnalyzerOption func(*ConnlistAnalyzer)

// WithLogger is a functional option which sets the logger for a ConnlistAnalyzer to use.
// The provided logger must conform with the package's Logger interface.
func WithLogger(l logger.Logger) ConnlistAnalyzerOption {
	return func(c *ConnlistAnalyzer) {
		c.logger = l
	}
}

// WithStopOnError is a functional option which directs ConnlistAnalyzer to stop any processing after the
// first severe error.
func WithStopOnError() ConnlistAnalyzerOption {
	return func(c *ConnlistAnalyzer) {
		c.stopOnError = true
	}
}

func WithFocusWorkload(workload string) ConnlistAnalyzerOption {
	return func(p *ConnlistAnalyzer) {
		p.focusWorkload = workload
	}
}

// WithExposureAnalysis is a functional option which directs ConnlistAnalyzer to perform exposure analysis
func WithExposureAnalysis() ConnlistAnalyzerOption {
	return func(c *ConnlistAnalyzer) {
		c.exposureAnalysis = true
		c.exposureResult = []ExposedPeer{}
	}
}

// WithOutputFormat is a functional option, allowing user to choose the output format txt/json/dot/csv/md.
func WithOutputFormat(outputFormat string) ConnlistAnalyzerOption {
	return func(p *ConnlistAnalyzer) {
		p.outputFormat = outputFormat
	}
}

// WithMuteErrsAndWarns is a functional option which directs ConnlistAnalyzer to avoid logging errors/warnings
func WithMuteErrsAndWarns() ConnlistAnalyzerOption {
	return func(c *ConnlistAnalyzer) {
		c.muteErrsAndWarns = true
	}
}

// NewConnlistAnalyzer creates a new instance of ConnlistAnalyzer, and applies the provided functional options.
func NewConnlistAnalyzer(options ...ConnlistAnalyzerOption) *ConnlistAnalyzer {
	// object with default behavior options
	ca := &ConnlistAnalyzer{
		logger:           logger.NewDefaultLogger(),
		stopOnError:      false,
		exposureAnalysis: false,
		exposureResult:   nil,
		errors:           []ConnlistError{},
		outputFormat:     output.DefaultFormat,
	}
	for _, o := range options {
		o(ca)
	}
	return ca
}

// Errors returns a slice of ConnlistError with all warnings and errors encountered during processing.
func (ca *ConnlistAnalyzer) Errors() []ConnlistError {
	return ca.errors
}

// ExposedPeers returns a slice of ExposedPeer objects,  capturing for input workloads if/how they  may
// be exposed to potential cluster entities, based on the input network policies
func (ca *ConnlistAnalyzer) ExposedPeers() []ExposedPeer {
	return ca.exposureResult
}

// return true if has fatal error or severe with flag stopOnError
func (ca *ConnlistAnalyzer) stopProcessing() bool {
	for idx := range ca.errors {
		if ca.errors[idx].IsFatal() || ca.stopOnError && ca.errors[idx].IsSevere() {
			return true
		}
	}
	return false
}

func (ca *ConnlistAnalyzer) hasFatalError() error {
	for idx := range ca.errors {
		if ca.errors[idx].IsFatal() {
			return ca.errors[idx].Error()
		}
	}
	return nil
}

// getPolicyEngine returns a new policy engine considering the exposure analysis option
func (ca *ConnlistAnalyzer) getPolicyEngine(objectsList []parser.K8sObject) (*eval.PolicyEngine, error) {
	// TODO: do we need logger in policyEngine?
	if !ca.exposureAnalysis {
		return eval.NewPolicyEngineWithObjects(objectsList)
	}
	// else build new policy engine with exposure analysis option
	pe := eval.NewPolicyEngineWithOptions(ca.exposureAnalysis)
	err := pe.AddObjects(objectsList)
	return pe, err
}

func (ca *ConnlistAnalyzer) connslistFromParsedResources(objectsList []parser.K8sObject) ([]Peer2PeerConnection, []Peer, error) {
	pe, err := ca.getPolicyEngine(objectsList)
	if err != nil {
		ca.errors = append(ca.errors, newResourceEvaluationError(err))
		return nil, nil, err
	}
	ia, err := ingressanalyzer.NewIngressAnalyzerWithObjects(objectsList, pe, ca.logger, ca.muteErrsAndWarns)
	if err != nil {
		ca.errors = append(ca.errors, newResourceEvaluationError(err))
		return nil, nil, err
	}
	return ca.getConnectionsList(pe, ia)
}

// ConnlistFromK8sCluster returns the allowed connections list from k8s cluster resources, and list of all peers names
func (ca *ConnlistAnalyzer) ConnlistFromK8sCluster(clientset *kubernetes.Clientset) ([]Peer2PeerConnection, []Peer, error) {
	pe := eval.NewPolicyEngineWithOptions(ca.exposureAnalysis)

	// get all resources from k8s cluster
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeoutSeconds*time.Second)
	defer cancel()

	// get all namespaces
	nsList, apierr := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if apierr != nil {
		return nil, nil, apierr
	}
	for i := range nsList.Items {
		ns := &nsList.Items[i]
		if err := pe.UpsertObject(ns); err != nil {
			return nil, nil, err
		}
	}

	// get all pods
	podList, apierr := clientset.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if apierr != nil {
		return nil, nil, apierr
	}
	for i := range podList.Items {
		if err := pe.UpsertObject(&podList.Items[i]); err != nil {
			return nil, nil, err
		}
	}

	// get all netpols
	npList, apierr := clientset.NetworkingV1().NetworkPolicies(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if apierr != nil {
		return nil, nil, apierr
	}
	for i := range npList.Items {
		if err := pe.UpsertObject(&npList.Items[i]); err != nil {
			return nil, nil, err
		}
	}
	return ca.getConnectionsList(pe, nil)
}

// ConnectionsListToString returns a string of connections from list of Peer2PeerConnection objects in the required output format
func (ca *ConnlistAnalyzer) ConnectionsListToString(conns []Peer2PeerConnection) (string, error) {
	connsFormatter, err := ca.getFormatter()
	if err != nil {
		ca.errors = append(ca.errors, newResultFormattingError(err))
		return "", err
	}
	out, err := connsFormatter.writeOutput(conns, ca.exposureResult)
	if err != nil {
		ca.errors = append(ca.errors, newResultFormattingError(err))
		return "", err
	}
	return out, nil
}

// validate the value of the output format
func ValidateOutputFormat(format string, exposureFlag bool) error {
	formatList := ValidFormats
	if exposureFlag {
		formatList = ExposureValidFormats
	}
	for _, formatName := range formatList {
		if format == formatName {
			return nil
		}
	}
	return errors.New(netpolerrors.FormatNotSupportedErrStr(format))
}

// returns the relevant formatter for the analyzer's outputFormat
func (ca *ConnlistAnalyzer) getFormatter() (connsFormatter, error) {
	if err := ValidateOutputFormat(ca.outputFormat, ca.exposureAnalysis); err != nil {
		return nil, err
	}
	switch ca.outputFormat {
	case output.JSONFormat:
		return &formatJSON{}, nil
	case output.TextFormat:
		return &formatText{}, nil
	case output.DOTFormat:
		return &formatDOT{}, nil
	case output.CSVFormat:
		return &formatCSV{}, nil
	case output.MDFormat:
		return &formatMD{}, nil
	default:
		return &formatText{}, nil
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////////////////
// internal type definitions below

const (
	ctxTimeoutSeconds = 3
)

// connection implements the Peer2PeerConnection interface
type connection struct {
	src               Peer
	dst               Peer
	allConnections    bool
	protocolsAndPorts map[v1.Protocol][]common.PortRange
}

func (c *connection) Src() Peer {
	return c.src
}
func (c *connection) Dst() Peer {
	return c.dst
}
func (c *connection) AllProtocolsAndPorts() bool {
	return c.allConnections
}
func (c *connection) ProtocolsAndPorts() map[v1.Protocol][]common.PortRange {
	return c.protocolsAndPorts
}

// returns a *common.ConnectionSet from Peer2PeerConnection data
func GetConnectionSetFromP2PConnection(c Peer2PeerConnection) *common.ConnectionSet {
	protocolsToPortSetMap := make(map[v1.Protocol]*common.PortSet, len(c.ProtocolsAndPorts()))
	for protocol, portRageArr := range c.ProtocolsAndPorts() {
		protocolsToPortSetMap[protocol] = common.MakePortSet(false)
		for _, p := range portRageArr {
			protocolsToPortSetMap[protocol].AddPortRange(p.Start(), p.End())
		}
	}
	connectionSet := &common.ConnectionSet{AllowAll: c.AllProtocolsAndPorts(), AllowedProtocols: protocolsToPortSetMap}
	return connectionSet
}

//////////////////////////////////////////////////////////////////////////////////////////////

func (ca *ConnlistAnalyzer) includePairOfWorkloads(pe *eval.PolicyEngine, src, dst eval.Peer) bool {
	if src.IsPeerIPType() && dst.IsPeerIPType() {
		return false
	}
	// skip self-looped connection,
	// i.e. a connection from workload to itself (regardless existence of replicas)
	if src.String() == dst.String() {
		return false
	}
	// when exposure-analysis, skip conns between fake pods or ip-peer and fake pods
	if ca.exposureAnalysis && !ca.includePairWithRepresentativePeer(pe, src, dst) {
		return false
	}
	if ca.focusWorkload == "" {
		return true
	}
	// at least one of src/dst should be the focus workload
	return ca.isPeerFocusWorkload(src) || ca.isPeerFocusWorkload(dst)
}

func (ca *ConnlistAnalyzer) includePairWithRepresentativePeer(pe *eval.PolicyEngine, src, dst eval.Peer) bool {
	isRepSrc := pe.IsRepresentativePeer(src)
	isRepDst := pe.IsRepresentativePeer(dst)
	// cases when at least one of the peers is representative peer; when not to include the peers pair:
	// both peers are Representative
	if isRepSrc && isRepDst {
		return false
	}
	// if one peer is IP and the other is a representative peer
	if (isRepSrc || isRepDst) && (src.IsPeerIPType() || dst.IsPeerIPType()) {
		return false
	}
	// if one peer is fake ingress-pod and the other is a representative peer
	// todo: might check if peer is a fake ingress-controller by checking name and fakePod flag (within new pe func)
	if (isRepSrc || isRepDst) && (src.Name() == common.IngressPodName || dst.Name() == common.IngressPodName) {
		return false
	}
	return true
}

func getPeerNsNameFormat(peer eval.Peer) string {
	return types.NamespacedName{Namespace: peer.Namespace(), Name: peer.Name()}.String()
}

func (ca *ConnlistAnalyzer) isPeerFocusWorkload(peer eval.Peer) bool {
	return !peer.IsPeerIPType() && (peer.Name() == ca.focusWorkload || getPeerNsNameFormat(peer) == ca.focusWorkload)
}

func convertEvalPeersToConnlistPeer(peers []eval.Peer) []Peer {
	res := make([]Peer, len(peers))
	for i, p := range peers {
		res[i] = p
	}
	return res
}

// getConnectionsList returns connections list from PolicyEngine and ingressAnalyzer objects
// if the exposure-analysis option is on, also computes and updates the exposure-analysis results
func (ca *ConnlistAnalyzer) getConnectionsList(pe *eval.PolicyEngine, ia *ingressanalyzer.IngressAnalyzer) ([]Peer2PeerConnection,
	[]Peer, error) {
	connsRes := make([]Peer2PeerConnection, 0)
	if !pe.HasPodPeers() {
		return connsRes, []Peer{}, nil
	}

	// get workload peers and ip blocks
	peerList, err := pe.GetPeersList()
	if err != nil {
		ca.errors = append(ca.errors, newResourceEvaluationError(err))
		return nil, nil, err
	}
	// represent peerList as []connlist.Peer list to be returned
	peers := convertEvalPeersToConnlistPeer(peerList)

	// connPeers represents []connlist.Peer to be sent to ca.getConnectionsBetweenPeers
	connPeers := peers
	if ca.exposureAnalysis {
		representativePeers := pe.GetRepresentativePeersList()
		connPeers = append(connPeers, convertEvalPeersToConnlistPeer(representativePeers)...)
	}

	excludeIngressAnalysis := (ia == nil || ia.IsEmpty())

	// if ca.focusWorkload is not empty, check if it exists in the peers before proceeding
	existFocusWorkload, warningMsg := ca.existsFocusWorkload(peers, excludeIngressAnalysis)
	if ca.focusWorkload != "" && !existFocusWorkload {
		ca.errors = append(ca.errors, newConnlistAnalyzerWarning(errors.New(warningMsg)))
		ca.logWarning(warningMsg)
		return nil, nil, nil
	}

	// compute connections between peers based on pe analysis of network policies
	// if exposure-analysis is on, also compute and return the exposures-map
	peersAllowedConns, exposureMaps, err := ca.getConnectionsBetweenPeers(pe, connPeers)
	if err != nil {
		ca.errors = append(ca.errors, newResourceEvaluationError(err))
		return nil, nil, err
	}
	connsRes = peersAllowedConns

	if ca.exposureAnalysis {
		ca.exposureResult = buildExposedPeerListFromExposureMaps(exposureMaps)
	}

	if excludeIngressAnalysis {
		return connsRes, peers, nil
	}

	// analyze ingress connections - create connection objects for relevant ingress analyzer connections
	ingressAllowedConns, err := ca.getIngressAllowedConnections(ia, pe)
	if err != nil {
		ca.errors = append(ca.errors, newResourceEvaluationError(err))
		return nil, nil, err
	}
	connsRes = append(connsRes, ingressAllowedConns...)

	if ca.focusWorkload == "" && len(peersAllowedConns) == 0 {
		ca.logWarning(netpolerrors.NoAllowedConnsWarning)
	}

	return connsRes, peers, nil
}

// existsFocusWorkload checks if the provided focus workload is ingress-controller
// or if it exists in the peers list from the parsed resources
// if not returns a suitable warning message
func (ca *ConnlistAnalyzer) existsFocusWorkload(peers []Peer, excludeIngressAnalysis bool) (existFocusWorkload bool, warning string) {
	if ca.focusWorkload == common.IngressPodName {
		if excludeIngressAnalysis { // if the ingress-analyzer is empty,
			// then no routes/k8s-ingress objects -> ingrss-controller pod will not be added
			return false, netpolerrors.NoIngressSourcesErrStr + netpolerrors.EmptyConnListErrStr
		}
		return true, ""
	}

	// check if the focusworkload is in the peers
	for _, peer := range peers {
		if ca.focusWorkload == peer.Name() || ca.focusWorkload == getPeerNsNameFormat(peer) {
			return true, ""
		}
	}
	return false, netpolerrors.WorkloadDoesNotExistErrStr(ca.focusWorkload)
}

// getConnectionsBetweenPeers returns connections list from PolicyEngine object
// and exposures-map containing the exposed peers data if the exposure-analysis is on , else empty map
func (ca *ConnlistAnalyzer) getConnectionsBetweenPeers(pe *eval.PolicyEngine, peers []Peer) ([]Peer2PeerConnection, *exposureMaps, error) {
	connsRes := make([]Peer2PeerConnection, 0)
	exposureMaps := &exposureMaps{
		ingressExposureMap: map[Peer]*peerXgressExposureData{},
		egressExposureMap:  map[Peer]*peerXgressExposureData{},
	}
	// for exposure-analysis use: sets for marking peer checked for ingress/egress exposure to entire cluster data once
	ingressSet := make(map[Peer]bool, 0)
	egressSet := make(map[Peer]bool, 0)

	for i := range peers {
		srcPeer := peers[i]
		for j := range peers {
			dstPeer := peers[j]
			if !ca.includePairOfWorkloads(pe, srcPeer, dstPeer) {
				continue
			}
			allowedConnections, err := pe.AllAllowedConnectionsBetweenWorkloadPeers(srcPeer, dstPeer)
			if err != nil {
				return nil, nil, err
			}
			if ca.exposureAnalysis {
				err = ca.updatePeersGeneralExposureData(pe, srcPeer, dstPeer, ingressSet, egressSet, exposureMaps)
				if err != nil {
					return nil, nil, err
				}
			}
			// skip empty connections
			if allowedConnections.IsEmpty() {
				continue
			}
			p2pConnection, err := ca.checkIfP2PConnOrExposureConn(pe, allowedConnections, srcPeer, dstPeer, exposureMaps)
			if err != nil {
				return nil, nil, err
			}
			if p2pConnection != nil {
				connsRes = append(connsRes, p2pConnection)
			}
		}
	}
	return connsRes, exposureMaps, nil
}

// getIngressAllowedConnections returns connections list from IngressAnalyzer intersected with PolicyEngine's connections
func (ca *ConnlistAnalyzer) getIngressAllowedConnections(ia *ingressanalyzer.IngressAnalyzer,
	pe *eval.PolicyEngine) ([]Peer2PeerConnection, error) {
	res := make([]Peer2PeerConnection, 0)
	ingressConns, err := ia.AllowedIngressConnections()
	if err != nil {
		return nil, err
	}
	// adding the ingress controller pod to the policy engine,
	ingressControllerPod, err := pe.AddPodByNameAndNamespace(common.IngressPodName, common.IngressPodNamespace, nil)
	if err != nil {
		return nil, err
	}
	for peerStr, peerAndConn := range ingressConns {
		// refines to only relevant connections if ca.focusWorkload is not empty
		if !ca.includePairOfWorkloads(pe, ingressControllerPod, peerAndConn.Peer) {
			continue
		}
		// compute allowed connections based on pe.policies to the peer, then intersect the conns with
		// ingress connections to the peer -> the intersection will be appended to the result
		peConn, err := pe.AllAllowedConnectionsBetweenWorkloadPeers(ingressControllerPod, peerAndConn.Peer)
		if err != nil {
			return nil, err
		}
		peerAndConn.ConnSet.Intersection(peConn)
		if peerAndConn.ConnSet.IsEmpty() {
			ca.warnBlockedIngress(peerStr, peerAndConn.IngressObjects)
			continue
		}
		p2pConnection := createConnectionObject(peerAndConn.ConnSet, ingressControllerPod, peerAndConn.Peer)
		res = append(res, p2pConnection)
	}
	return res, nil
}

func (ca *ConnlistAnalyzer) warnBlockedIngress(peerStr string, ingressObjs map[string][]string) {
	objKind := ""
	objName := ""
	if len(ingressObjs[parser.Ingress]) > 0 {
		objKind = "K8s-Ingress"
		objName = ingressObjs[parser.Ingress][0]
	} else if len(ingressObjs[parser.Route]) > 0 {
		objKind = "Route"
		objName = ingressObjs[parser.Route][0]
	}
	warningMsg := netpolerrors.BlockedIngressWarning(objKind, objName, peerStr)
	ca.errors = append(ca.errors, newConnlistAnalyzerWarning(errors.New(warningMsg)))
	ca.logWarning(warningMsg)
}

func (ca *ConnlistAnalyzer) logWarning(msg string) {
	if !ca.muteErrsAndWarns {
		ca.logger.Warnf(msg)
	}
}

// checkIfP2PConnOrExposureConn checks if the given connection is between two peers from the parsed resources, if yes returns it,
// otherwise the connection belongs to exposure-analysis, will be added to the provided map
func (ca *ConnlistAnalyzer) checkIfP2PConnOrExposureConn(pe *eval.PolicyEngine, allowedConnections common.Connection,
	src, dst Peer, exposureMaps *exposureMaps) (*connection, error) {
	if !ca.exposureAnalysis {
		// if exposure analysis option is off , the connection is definitely a P2PConnection
		return createConnectionObject(allowedConnections, src, dst), nil
	}
	// else exposure analysis is on

	if !pe.IsRepresentativePeer(src) && !pe.IsRepresentativePeer(dst) {
		// both src and dst are peers are found in the parsed resources (and IPs)
		return createConnectionObject(allowedConnections, src, dst), nil
	}
	// else: one of the peers is a representative peer (inferred from a netpol-rule) ,
	// and the other is a peer from the parsed resources
	// an exposure analysis connection
	isIngress := pe.IsRepresentativePeer(src)
	err := exposureMaps.addConnToExposureMap(pe, allowedConnections, src, dst, isIngress)
	return nil, err
}

// helper function - returns a connection object from the given fields
func createConnectionObject(allowedConnections common.Connection, src, dst Peer) *connection {
	return &connection{
		src:               src,
		dst:               dst,
		allConnections:    allowedConnections.AllConnections(),
		protocolsAndPorts: allowedConnections.ProtocolsAndPortsMap(),
	}
}

// updatePeersGeneralExposureData updates src and dst connections to entire world/cluster on the exposures map
func (ca *ConnlistAnalyzer) updatePeersGeneralExposureData(pe *eval.PolicyEngine, src, dst Peer, ingressSet, egressSet map[Peer]bool,
	exMaps *exposureMaps) error {
	// when computing allowed conns between the peers,(even on first time)
	// if a workload peer is not protected by netpols this was definitely detected;
	// also exposure to entire cluster was definitely computed for src or/and dst (if its a workload peer)
	// so we should update the unprotected / entire connection cluster in the map for those real workload peers
	// this way we ensure updating the xgress exposure data to entire cluster/world of the peer's entry
	// in the exposure map before adding any other connection
	// or we might also have a case of no other exposure conns
	// (e.g. only one peer with one netpol exposing the peer to entire cluster, no netpols)
	var err error
	// 1. only on first time : add general exposure data for the src peer (on egress)
	if ca.shouldAddPeerGeneralExposureData(pe, src, egressSet) {
		err = exMaps.addPeerGeneralExposure(pe, src, false)
		if err != nil {
			return err
		}
	}
	egressSet[src] = true
	// 2. only on first time : add general exposure data for the dst peer (on ingress)
	if ca.shouldAddPeerGeneralExposureData(pe, dst, ingressSet) {
		err = exMaps.addPeerGeneralExposure(pe, dst, true)
	}
	ingressSet[dst] = true
	return err
}

// shouldAddPeerGeneralExposureData returns whether should add given peer's general
// exposure data to the exposure results.
// returns true if :
// - the peer is not IP type
// - the peer is not representative peer
// - focus-workload flag is not used or the peer is the focus-workload
// - it is first time the peer is visited
func (ca *ConnlistAnalyzer) shouldAddPeerGeneralExposureData(pe *eval.PolicyEngine, peer Peer, xgressSet map[Peer]bool) bool {
	return !peer.IsPeerIPType() && !pe.IsRepresentativePeer(peer) && !xgressSet[peer] &&
		(ca.focusWorkload == "" || ca.isPeerFocusWorkload(peer))
}
