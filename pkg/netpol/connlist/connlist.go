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
	"path/filepath"
	"time"

	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	v1 "k8s.io/api/core/v1"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/common"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/connlist/internal/ingressanalyzer"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/logger"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/scan"
)

// A ConnlistAnalyzer provides API to recursively scan a directory for Kubernetes resources including network policies,
// and get the list of permitted connectivity between the workloads of the K8s application managed in this directory.
type ConnlistAnalyzer struct {
	logger               logger.Logger
	stopOnError          bool
	errors               []ConnlistError
	walkFn               scan.WalkFunction
	scanner              *scan.ResourcesScanner
	focusWorkload        string
	outputFormat         string
	includeJSONManifests bool
}

// ValidFormats array of possible values of output format
var ValidFormats = []string{common.TextFormat, common.JSONFormat, common.DOTFormat,
	common.CSVFormat, common.MDFormat}

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

// WithIncludeJSONManifests is a functional option which directs ConnlistAnalyzer to include JSON manifests in the analysis
func WithIncludeJSONManifests() ConnlistAnalyzerOption {
	return func(c *ConnlistAnalyzer) {
		c.includeJSONManifests = true
	}
}

// WithWalkFn is a functional option, allowing user to provide their own dir-scanning function.
// It is relevant when using ConnlistAnalyzer to analyze connectivity from scanned dir resources.
func WithWalkFn(walkFn scan.WalkFunction) ConnlistAnalyzerOption {
	return func(c *ConnlistAnalyzer) {
		c.walkFn = walkFn
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

// NewConnlistAnalyzer creates a new instance of ConnlistAnalyzer, and applies the provided functional options.
func NewConnlistAnalyzer(options ...ConnlistAnalyzerOption) *ConnlistAnalyzer {
	// object with default behavior options
	ca := &ConnlistAnalyzer{
		logger:       logger.NewDefaultLogger(),
		stopOnError:  false,
		errors:       []ConnlistError{},
		walkFn:       filepath.WalkDir,
		outputFormat: common.DefaultFormat,
	}
	for _, o := range options {
		o(ca)
	}
	ca.scanner = scan.NewResourcesScanner(ca.logger, ca.stopOnError, ca.walkFn, ca.includeJSONManifests)
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

// ConnlistFromDirPath returns the allowed connections list from dir path containing k8s resources
// and list of all workloads from the parsed resources
func (ca *ConnlistAnalyzer) ConnlistFromDirPath(dirPath string) ([]Peer2PeerConnection, []Peer, error) {
	objectsList, processingErrs := ca.scanner.FilesToObjectsList(dirPath)
	for i := range processingErrs {
		ca.errors = append(ca.errors, &processingErrs[i])
	}

	if ca.stopProcessing() {
		if err := ca.hasFatalError(); err != nil {
			return nil, nil, err
		}
		return []Peer2PeerConnection{}, []Peer{}, nil
	}
	return ca.connslistFromParsedResources(objectsList)
}

// ConnlistFromYAMLManifests returns the allowed connections list from input YAML manifests
// and list of all workloads from the parsed resources
func (ca *ConnlistAnalyzer) ConnlistFromYAMLManifests(manifests []scan.YAMLDocumentIntf) ([]Peer2PeerConnection, []Peer, error) {
	objectsList, processingErrs := ca.scanner.YAMLDocumentsToObjectsList(manifests)
	for i := range processingErrs {
		ca.errors = append(ca.errors, &processingErrs[i])
	}

	if ca.stopProcessing() {
		if err := ca.hasFatalError(); err != nil {
			return nil, nil, err
		}
		return []Peer2PeerConnection{}, []Peer{}, nil
	}

	return ca.connslistFromParsedResources(objectsList)
}

func (ca *ConnlistAnalyzer) connslistFromParsedResources(objectsList []scan.K8sObject) ([]Peer2PeerConnection, []Peer, error) {
	// TODO: do we need logger in policyEngine?
	pe, err := eval.NewPolicyEngineWithObjects(objectsList)
	if err != nil {
		ca.errors = append(ca.errors, newResourceEvaluationError(err))
		return nil, nil, err
	}
	ia, err := ingressanalyzer.NewIngressAnalyzerWithObjects(objectsList, pe, ca.logger)
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
	output, err := connsFormatter.writeOutput(conns)
	if err != nil {
		ca.errors = append(ca.errors, newResultFormattingError(err))
		return "", err
	}
	return output, nil
}

// validate the value of the output format
func ValidateOutputFormat(format string) error {
	for _, formatName := range ValidFormats {
		if format == formatName {
			return nil
		}
	}
	return errors.New(format + " output format is not supported.")
}

// returns the relevant formatter for the analyzer's outputFormat
func getFormatter(format string) (connsFormatter, error) {
	if err := ValidateOutputFormat(format); err != nil {
		return nil, err
	}
	switch format {
	case common.JSONFormat:
		return formatJSON{}, nil
	case common.TextFormat:
		return formatText{}, nil
	case common.DOTFormat:
		return formatDOT{}, nil
	case common.CSVFormat:
		return formatCSV{}, nil
	case common.MDFormat:
		return formatMD{}, nil
	default:
		return formatText{}, nil
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////////////////
// internal type definitions below

const (
	connsAndPortRangeSeparator = ","
	ctxTimeoutSeconds          = 3
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

// return a string representation of a connection type (protocols and ports)
func GetProtocolsAndPortsStr(c Peer2PeerConnection) string {
	if c.AllProtocolsAndPorts() {
		return "All Connections"
	}
	if len(c.ProtocolsAndPorts()) == 0 {
		return "No Connections"
	}
	var connStr string
	connStrings := make([]string, len(c.ProtocolsAndPorts()))
	index := 0
	for protocol, ports := range c.ProtocolsAndPorts() {
		connStrings[index] = string(protocol) + " " + portsString(ports)
		index++
	}
	sort.Strings(connStrings)
	connStr = strings.Join(connStrings, connsAndPortRangeSeparator)
	return connStr
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

func getPeerNsNameFormat(eval.Peer) string {
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

	excludeIngressAnalysis := (ia == nil || ia.IsEmpty())

	// if ca.focusWorkload is not empty, check if it exists in the peerList before proceeding
	if ca.focusWorkload != "" && !ca.existsFocusWorkload(peerList, excludeIngressAnalysis) {
		warnMsg := "workload " + ca.focusWorkload + " does not exist in the input resources. Connectivity map report will be empty."
		ca.errors = append(ca.errors, newConnlistAnalyzerWarning(errors.New(warnMsg)))
		ca.logger.Warnf(warnMsg)
		return nil, nil, nil
	}

	// represent peerList as []connlist.Peer list to be returned
	peers := make([]Peer, len(peerList))
	for i, p := range peerList {
		peers[i] = p
	}

	// compute connections between peers based on pe analysis of network policies
	peersAllowedConns, err := ca.getConnectionsBetweenPeers(pe, peerList)
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
		ca.logger.Warnf("connectivity analysis found no allowed connectivity between pairs from the configured workloads or external IP-blocks")
	}

	return connsRes, peers, nil
}

// existsFocusWorkload checks if the provided focus workload is ingress-controller
// or if it exists in the peers list from the parsed resources
func (ca *ConnlistAnalyzer) existsFocusWorkload(peerList []eval.Peer, excludeIA bool) bool {
	// if focus workload is ingress controller, it is okay to continue checking for connections
	ingressPodNsNameFormat := types.NamespacedName{Namespace: ingressanalyzer.IngressPodNamespace,
		Name: ingressanalyzer.IngressPodName}.String()
	if ca.focusWorkload == ingressanalyzer.IngressPodName || ca.focusWorkload == ingressPodNsNameFormat {
		return !excludeIA // if the ingress-analyzer is empty,
		// then no routes/k8s-ingress objects -> ingrss-controller pod will not be added
	}

	// check if the focusworkload is in the peerList
	for _, peer := range peerList {
		peerNsNameFormat := types.NamespacedName{Namespace: peer.Namespace(), Name: peer.Name()}.String()
		if ca.focusWorkload == peer.Name() || ca.focusWorkload == peerNsNameFormat {
			return true
		}
	}
	return false
}

// getConnectionsBetweenPeers returns connections list from PolicyEngine object
func (ca *ConnlistAnalyzer) getConnectionsBetweenPeers(pe *eval.PolicyEngine, peerList []eval.Peer) ([]Peer2PeerConnection, error) {
	connsRes := make([]Peer2PeerConnection, 0)
	for i := range peerList {
		srcPeer := peerList[i]
		for j := range peerList {
			dstPeer := peerList[j]
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
	ingressConns, err := ia.AllowedIngressConnections()
	if err != nil {
		return nil, err
	}
	// adding the ingress controller pod to the policy engine,
	ingressControllerPod, err := pe.AddPodByNameAndNamespace(ingressanalyzer.IngressPodName, ingressanalyzer.IngressPodNamespace)
	if err != nil {
		return nil, err
	}
	for peerStr, peerAndConn := range ingressConns {
		// refines to only relevant connections if ca.focusWorkload is not empty
		if !ca.includePairOfWorkloads(ingressControllerPod, peerAndConn.Peer) {
			continue
		}
		// compute allowed connections based on pe.policies to the peer, then intersect the conns with
		// ingress connections to the peer -> the intersection will be appended to the result
		peConn, err := pe.AllAllowedConnectionsBetweenWorkloadPeers(ingressControllerPod, peerAndConn.Peer)
		if err != nil {
			return nil, err
		}
		peerAndConn.ConnSet.Intersection(peConn.(*common.ConnectionSet))
		if peerAndConn.ConnSet.IsEmpty() {
			ca.warnBlockedIngress(peerStr, peerAndConn.IngressObjects)
			continue
		}
		p2pConnection := &connection{
			src:               ingressControllerPod,
			dst:               peerAndConn.Peer,
			allConnections:    peerAndConn.ConnSet.AllConnections(),
			protocolsAndPorts: peerAndConn.ConnSet.ProtocolsAndPortsMap(),
		}
		res = append(res, p2pConnection)
	}
	return res, nil
}

// get string representation for a list of port ranges
func portsString(ports []common.PortRange) string {
	portsStr := make([]string, len(ports))
	for i := range ports {
		portsStr[i] = ports[i].String()
	}
	return strings.Join(portsStr, connsAndPortRangeSeparator)
}

func (ca *ConnlistAnalyzer) warnBlockedIngress(peerStr string, ingressObjs map[string][]string) {
	warningMsg := ""
	if len(ingressObjs[scan.Ingress]) > 0 {
		warningMsg = "K8s-Ingress resource " + ingressObjs[scan.Ingress][0]
	} else if len(ingressObjs[scan.Route]) > 0 {
		warningMsg = "Route resource " + ingressObjs[scan.Route][0]
	}
	warningMsg += " specified workload " + peerStr + " as a backend, but network policies are blocking " +
		"ingress connections from an arbitrary in-cluster source to this workload. " +
		"Connectivity map will not include a possibly allowed connection between the ingress controller and this workload."
	ca.errors = append(ca.errors, newConnlistAnalyzerWarning(errors.New(warningMsg)))
	ca.logger.Warnf(warningMsg)
}
