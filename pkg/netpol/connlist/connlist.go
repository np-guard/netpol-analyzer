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

// ConnlistFromDirPath returns the allowed connections list from dir path containing k8s resources
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
		logger:       logger.NewDefaultLogger(),
		stopOnError:  false,
		errors:       []ConnlistError{},
		outputFormat: output.DefaultFormat,
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

func (ca *ConnlistAnalyzer) connslistFromParsedResources(objectsList []parser.K8sObject) ([]Peer2PeerConnection, []Peer, error) {
	// TODO: do we need logger in policyEngine?
	pe, err := eval.NewPolicyEngineWithObjects(objectsList)
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

// ConnlistFromK8sCluster returns the allowed connections list from k8s cluster resources and a list of all peers names
func (ca *ConnlistAnalyzer) ConnlistFromK8sCluster(clientset *kubernetes.Clientset) ([]Peer2PeerConnection, []Peer, error) {
	pe := eval.NewPolicyEngine()

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
	connsFormatter, err := getFormatter(ca.outputFormat)
	if err != nil {
		ca.errors = append(ca.errors, newResultFormattingError(err))
		return "", err
	}
	out, err := connsFormatter.writeOutput(conns)
	if err != nil {
		ca.errors = append(ca.errors, newResultFormattingError(err))
		return "", err
	}
	return out, nil
}

// validate the value of the output format
func ValidateOutputFormat(format string) error {
	for _, formatName := range ValidFormats {
		if format == formatName {
			return nil
		}
	}
	return errors.New(netpolerrors.FormatNotSupportedErrStr(format))
}

// returns the relevant formatter for the analyzer's outputFormat
func getFormatter(format string) (connsFormatter, error) {
	if err := ValidateOutputFormat(format); err != nil {
		return nil, err
	}
	switch format {
	case output.JSONFormat:
		return formatJSON{}, nil
	case output.TextFormat:
		return formatText{}, nil
	case output.DOTFormat:
		return formatDOT{}, nil
	case output.CSVFormat:
		return formatCSV{}, nil
	case output.MDFormat:
		return formatMD{}, nil
	default:
		return formatText{}, nil
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
		protocolsToPortSetMap[protocol] = &common.PortSet{}
		for _, portRange := range portRageArr {
			protocolsToPortSetMap[protocol].AddPortRange(portRange.Start(), portRange.End())
		}
	}
	connectionSet := &common.ConnectionSet{AllowAll: c.AllProtocolsAndPorts(), AllowedProtocols: protocolsToPortSetMap}
	return connectionSet
}

//////////////////////////////////////////////////////////////////////////////////////////////

func (ca *ConnlistAnalyzer) includePairOfWorkloads(src, dst eval.Peer) bool {
	if src.IsPeerIPType() && dst.IsPeerIPType() {
		return false
	}
	// skip self-looped connection,
	// i.e. a connection from workload to itself (regardless existence of replicas)
	if src.String() == dst.String() {
		return false
	}
	if ca.focusWorkload == "" {
		return true
	}
	// at least one of src/dst should be the focus workload
	return ca.isPeerFocusWorkload(src) || ca.isPeerFocusWorkload(dst)
}

func getPeerNsNameFormat(peer eval.Peer) string {
	return types.NamespacedName{Namespace: peer.Namespace(), Name: peer.Name()}.String()
}

func (ca *ConnlistAnalyzer) isPeerFocusWorkload(peer eval.Peer) bool {
	return !peer.IsPeerIPType() && (peer.Name() == ca.focusWorkload || getPeerNsNameFormat(peer) == ca.focusWorkload)
}

// getConnectionsList returns connections list from PolicyEngine and ingressAnalyzer objects
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
	peers := make([]Peer, len(peerList))
	for i, p := range peerList {
		peers[i] = p
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
	peersAllowedConns, err := ca.getConnectionsBetweenPeers(pe, peers)
	if err != nil {
		ca.errors = append(ca.errors, newResourceEvaluationError(err))
		return nil, nil, err
	}
	connsRes = peersAllowedConns

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
func (ca *ConnlistAnalyzer) getConnectionsBetweenPeers(pe *eval.PolicyEngine, peers []Peer) ([]Peer2PeerConnection, error) {
	connsRes := make([]Peer2PeerConnection, 0)
	for i := range peers {
		srcPeer := peers[i]
		for j := range peers {
			dstPeer := peers[j]
			if !ca.includePairOfWorkloads(srcPeer, dstPeer) {
				continue
			}
			allowedConnections, err := pe.AllAllowedConnectionsBetweenWorkloadPeers(srcPeer, dstPeer)
			if err != nil {
				return nil, err
			}
			// skip empty connections
			if allowedConnections.IsEmpty() {
				continue
			}
			p2pConnection := &connection{
				src:               srcPeer,
				dst:               dstPeer,
				allConnections:    allowedConnections.AllConnections(),
				protocolsAndPorts: allowedConnections.ProtocolsAndPortsMap(),
			}
			connsRes = append(connsRes, p2pConnection)
		}
	}

	return connsRes, nil
}

// getIngressAllowedConnections returns connections list from IngressAnalyzer intersected with PolicyEngine's connections
func (ca *ConnlistAnalyzer) getIngressAllowedConnections(ia *ingressanalyzer.IngressAnalyzer,
	pe *eval.PolicyEngine) ([]Peer2PeerConnection, error) {
	res := make([]Peer2PeerConnection, 0)
	// ingress connections enabled by Ingress/Route objects
	ingressConns, err := ia.AllowedIngressConnections()
	if err != nil {
		return nil, err
	}
	// adding specific known controller pods to the policy engine
	specificIngressControllers, err := addSpecificIngressControllers(pe)
	if err != nil {
		return nil, err
	}
	// 3. computing allowed connections by Ingress controllers for peers that are selected by Ingress/Route objects
	for peerStr, peerAndConn := range ingressConns {
		// check if ingress is allowed from a specific known ingress controller
		foundIngressConns := false
		for _, ingPod := range specificIngressControllers {
			ingConn, err := ca.allowedIngressControllerToPeerFromPoliciesRules(ingPod, peerAndConn.Peer, pe)
			if err != nil {
				return nil, err
			}
			if ingConn == nil {
				continue
			}
			(ingConn.(*common.ConnectionSet)).Intersection(peerAndConn.ConnSet)
			if !ingConn.IsEmpty() {
				foundIngressConns = true
				p2pConnection := &connection{
					src:               ingPod,
					dst:               peerAndConn.Peer,
					allConnections:    ingConn.AllConnections(),
					protocolsAndPorts: ingConn.ProtocolsAndPortsMap(),
				}
				res = append(res, p2pConnection)
			}
		}
		if !foundIngressConns { // specific ingress controller conn to this peer is not allowed
			ca.warnBlockedIngress(peerStr, peerAndConn.IngressObjects)
		}
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

// helping func - adds new fake pods in ingress controllers namespaces to the policy engine
func addSpecificIngressControllers(pe *eval.PolicyEngine) ([]Peer, error) {
	res := []Peer{}
	for _, ns := range common.SpecificIngressControllersNs {
		ingPod, err := pe.AddPodByNameAndNamespace(common.IngressPodName, ns)
		if err != nil {
			return nil, err
		}
		res = append(res, ingPod)
	}
	return res, nil
}

func (ca *ConnlistAnalyzer) allowedIngressControllerToPeerFromPoliciesRules(ingressPeer, dst Peer,
	pe *eval.PolicyEngine) (common.Connection, error) {
	// refines to only relevant connections if ca.focusWorkload is not empty
	if !ca.includePairOfWorkloads(ingressPeer, dst) {
		return nil, nil
	}
	peConn, err := pe.AllAllowedConnectionsBetweenWorkloadPeers(ingressPeer, dst)
	if err != nil {
		return nil, err
	}
	return peConn, nil
}
