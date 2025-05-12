/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// The connlist package of netpol-analyzer allows producing a k8s connectivity report based on several resources:
// k8s NetworkPolicy & AdminNetworkPolicy & BaselineAdminNetworkPolicy, k8s Ingress, openshift Route
// It lists the set of allowed connections between each pair of different peers (k8s workloads or ip-blocks).
// Connections between workload to itself are excluded from the output.
// Connectivity inferred from Ingress/Route resources is between {ingress-controller} to k8s workloads.
// The resources can be extracted from a directory containing YAML manifests, or from a k8s cluster.
// For more information, see https://github.com/np-guard/netpol-analyzer.
package connlist

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	policyapi "sigs.k8s.io/network-policy-api/pkg/client/clientset/versioned"

	v1 "k8s.io/api/core/v1"

	"k8s.io/cli-runtime/pkg/resource"

	pkgcommon "github.com/np-guard/netpol-analyzer/pkg/internal/common"
	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
	"github.com/np-guard/netpol-analyzer/pkg/internal/output"
	"github.com/np-guard/netpol-analyzer/pkg/logger"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/fsscanner"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/parser"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/connlist/internal/ingressanalyzer"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/alerts"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// A ConnlistAnalyzer provides API to recursively scan a directory for Kubernetes resources including network policies,
// and get the list of permitted connectivity between the workloads of the K8s application managed in this directory.
type ConnlistAnalyzer struct {
	logger             logger.Logger
	stopOnError        bool
	errors             []ConnlistError
	focusWorkloads     []string
	focusWorkloadPeers []string
	focusDirection     string
	exposureAnalysis   bool
	exposureResult     []ExposedPeer
	explain            bool
	explainOnly        string
	focusConnection    string
	outputFormat       string
	muteErrsAndWarns   bool
	peersList          []Peer // internally used peersList used in dot/svg formatting;
	// in case of focusWorkload option contains only relevant peers
	primaryUdnNamespaces map[string]bool // set of the names of isolated by primary UDN namespaces,
	// internally used in formatting output
	focusConnSet *common.ConnectionSet // internally used to focus conns list results with this specific connection
}

const (
	focusworkloadStr     = "focusworkload"
	focusWorkloadPeerStr = "focusworkload-peer"
	explainStr           = "explain"
	explainOnlyStr       = "explain-only"
)

// some notes on flags combinations :
// - `focus-direction` is effective only with `focusworkload` (workloads list); otherwise ignored
// - `focusworkload-peer` is effective only with `focusworkload`; otherwise ignored
// - `exposure` is not relevant if both focusworkload-peer` and `focusworkload` are used; in this case `exposure` is ignored
// - `explain-only` is effective only with `explain`; otherwise ignored
// - `exposure` is not relevant if both `explain` and `explain-only` are used; in this case `exposure` is ignored
// - `explain` is effective only with output format `output` txt
func (ca *ConnlistAnalyzer) warnIncompatibleFlagsUsage() {
	if ca.explain && ca.outputFormat != output.DefaultFormat {
		ca.logWarning(alerts.WarnIncompatibleFormat(ca.outputFormat))
	}
	if len(ca.focusWorkloads) == 0 && ca.focusDirection != "" {
		ca.logWarning(alerts.FocusDirectionFlag + alerts.WarnIgnoredWithoutFocusWorkload)
	}
	if len(ca.focusWorkloads) == 0 && len(ca.focusWorkloadPeers) != 0 {
		ca.logWarning(alerts.FocusWorkloadPeerFlag + alerts.WarnIgnoredWithoutFocusWorkload)
	}
	if len(ca.focusWorkloads) > 0 && len(ca.focusWorkloadPeers) > 0 && ca.exposureAnalysis {
		ca.exposureAnalysis = false
		ca.logWarning(alerts.WarnIgnoredExposure(focusworkloadStr, focusWorkloadPeerStr))
	}
	if !ca.explain && ca.explainOnly != "" {
		ca.explainOnly = ""
		ca.logWarning(alerts.WarnIgnoredWithoutExplain)
	}
	if ca.explain && ca.explainOnly != "" && ca.exposureAnalysis {
		ca.exposureAnalysis = false
		ca.logWarning(alerts.WarnIgnoredExposure(explainStr, explainOnlyStr))
	}
}

// The new interface
// ConnlistFromResourceInfos returns the allowed-connections list from input slice of resource.Info objects,
// and the list of all workloads from the parsed resources
func (ca *ConnlistAnalyzer) ConnlistFromResourceInfos(info []*resource.Info) ([]Peer2PeerConnection, []Peer, error) {
	// convert resource.Info objects to k8s resources, filter irrelevant resources
	objects, fpErrs := parser.ResourceInfoListToK8sObjectsList(info, ca.logger, ca.muteErrsAndWarns)
	ca.copyFpErrs(fpErrs)
	if ca.stopProcessing() {
		if err := ca.hasFatalError(); err != nil {
			return nil, nil, err
		}
		return []Peer2PeerConnection{}, []Peer{}, nil
	}
	return ca.connsListFromParsedResources(objects)
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
	output.CSVFormat, output.MDFormat, output.SVGFormat}

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

// WithFocusWorkloadList is a functional option which directs ConnlistAnalyzer to focus connections of specified workloads in the output
func WithFocusWorkloadList(workloads []string) ConnlistAnalyzerOption {
	return func(p *ConnlistAnalyzer) {
		p.focusWorkloads = workloads
	}
}

// Deprecated
func WithFocusWorkload(workload string) ConnlistAnalyzerOption {
	return func(p *ConnlistAnalyzer) {
		p.focusWorkloads = []string{workload}
	}
}

// WithFocusDirection is a functional option which directs ConnlistAnalyzer to focus connections of specified workloads on one direction
func WithFocusDirection(direction string) ConnlistAnalyzerOption {
	return func(p *ConnlistAnalyzer) {
		p.focusDirection = direction
	}
}

func WithFocusConnection(focusConn string) ConnlistAnalyzerOption {
	return func(p *ConnlistAnalyzer) {
		p.focusConnection = focusConn
	}
}

// WithFocusWorkloadPeerList is a functional option which directs ConnlistAnalyzer to focus connections of specified workloads
// with given peers
func WithFocusWorkloadPeerList(workloadPeers []string) ConnlistAnalyzerOption {
	return func(p *ConnlistAnalyzer) {
		p.focusWorkloadPeers = workloadPeers
	}
}

// WithExposureAnalysis is a functional option which directs ConnlistAnalyzer to perform exposure analysis
func WithExposureAnalysis() ConnlistAnalyzerOption {
	return func(c *ConnlistAnalyzer) {
		c.exposureAnalysis = true
		c.exposureResult = []ExposedPeer{}
	}
}

// WithExplanation is a functional option which directs ConnlistAnalyzer to return explainability of connectivity
func WithExplanation() ConnlistAnalyzerOption {
	return func(c *ConnlistAnalyzer) {
		c.explain = true
	}
}

// WithExplainOnly is a functional option which directs ConnlistAnalyzer to filter explain output to show only allowed or denied connections
func WithExplainOnly(explainOnly string) ConnlistAnalyzerOption {
	return func(c *ConnlistAnalyzer) {
		c.explainOnly = explainOnly
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
		explain:          false,
		errors:           []ConnlistError{},
		outputFormat:     output.DefaultFormat,
	}
	for _, o := range options {
		o(ca)
	}
	ca.warnIncompatibleFlagsUsage()
	return ca
}

func (ca *ConnlistAnalyzer) validateFocusDirectionValue() error {
	if ca.focusDirection != "" && ca.focusDirection != pkgcommon.IngressFocusDirection &&
		ca.focusDirection != pkgcommon.EgressFocusDirection {
		return errors.New(alerts.FocusDirectionNotSupported(ca.focusDirection))
	}
	return nil
}

func (ca *ConnlistAnalyzer) validateExplainOnlyValue() error {
	if ca.explainOnly != "" && ca.explainOnly != pkgcommon.ExplainOnlyAllow &&
		ca.explainOnly != pkgcommon.ExplainOnlyDeny {
		return errors.New(alerts.ExplainOnlyNotSupported(ca.explainOnly))
	}
	return nil
}

const focusConnDelimiter = "-"

// makeFocusConnectionSet stores in ca.focusConnSet a connection set from parsed ca.focusConnection string
func (ca *ConnlistAnalyzer) makeFocusConnectionSet(protocol string, portNum int) {
	ca.focusConnSet = common.MakeConnectionSet(false)
	focusPort := common.MakePortSet(false)
	focusPort.AddPort(intstr.FromInt(portNum), common.ImplyingRulesType{})
	ca.focusConnSet.AddConnection(v1.Protocol(strings.ToUpper(protocol)), focusPort)
}

// validateFocusConnFormatAndValue validates focus connection format is <protocol-port> with valid protocol and port values
// and if valid : make connections with the protocol and port
func (ca *ConnlistAnalyzer) validateFocusConnFormatAndValue() error {
	if ca.focusConnection == "" {
		return nil
	}
	connArr := strings.Split(ca.focusConnection, focusConnDelimiter)
	if len(connArr) != 2 {
		return errors.New(alerts.InvalidFocusConnFormat(ca.focusConnection))
	}
	protocol := connArr[0]
	if !common.IsProtocolValid(protocol) {
		return errors.New(alerts.InvalidFocusConnProtocol(ca.focusConnection, protocol))
	}
	portNum, err := strconv.Atoi(connArr[1])
	if err != nil || (int64(portNum) < common.MinPort || int64(portNum) > common.MaxPort) {
		return errors.New(alerts.InvalidFocusConnPortNumber(ca.focusConnection, connArr[1]))
	}
	// valid - make connection set with the protocol and port to be used internally for conns filtering
	ca.makeFocusConnectionSet(protocol, portNum)
	return nil
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
	if !ca.exposureAnalysis {
		return eval.NewPolicyEngineWithOptionsList(eval.WithExplanation(ca.explain),
			eval.WithLogger(ca.logger), eval.WithObjectsList(objectsList))
	}
	// else build new policy engine with exposure analysis option
	return eval.NewPolicyEngineWithOptionsList(eval.WithExposureAnalysis(), eval.WithExplanation(ca.explain),
		eval.WithLogger(ca.logger), eval.WithObjectsList(objectsList))
}

func (ca *ConnlistAnalyzer) connsListFromParsedResources(objectsList []parser.K8sObject) ([]Peer2PeerConnection, []Peer, error) {
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
	ca.primaryUdnNamespaces = pe.GetPrimaryUDNNamespaces()
	return ca.getConnectionsList(pe, ia)
}

// ConnlistFromK8sClusterWithPolicyAPI returns the allowed connections list from k8s cluster resources, and list of all peers names
func (ca *ConnlistAnalyzer) ConnlistFromK8sClusterWithPolicyAPI(clientset kubernetes.Interface,
	policyAPIClientset policyapi.Interface) ([]Peer2PeerConnection, []Peer, error) {
	pe, err := eval.NewPolicyEngineWithOptionsList(eval.WithExplanation(ca.explain), eval.WithLogger(ca.logger))
	if ca.exposureAnalysis {
		pe, err = eval.NewPolicyEngineWithOptionsList(eval.WithExplanation(ca.explain), eval.WithLogger(ca.logger), eval.WithExposureAnalysis())
	}
	if err != nil {
		return nil, nil, err
	}
	// adding objects to policy-engine will be in the order : Namespaces, policies (NetworkPolicy, AdminNetworkPolicy
	// and BaselineAdminNetworkPolicy) then Pods
	// this order is necessary when exposure-analysis is on.

	// 1. insert namespaces from k8s clientset
	err = updatePolicyEngineWithNamespaces(pe, clientset)
	if err != nil {
		return nil, nil, err
	}

	// 2. insert network-policies from  k8s clientset and admin policies from k8s policy-api clientset
	err = updatePolicyEngineWithNetworkPolicies(pe, clientset)
	if err != nil {
		return nil, nil, err
	}
	err = pe.UpdatePolicyEngineWithK8sPolicyAPIObjects(policyAPIClientset)
	if err != nil {
		return nil, nil, err
	}

	// 3. insert pods from k8s clientset
	err = updatePolicyEngineWithPods(pe, clientset)
	if err != nil {
		return nil, nil, err
	}

	return ca.getConnectionsList(pe, nil)
}

// updatePolicyEngineWithNamespaces inserts to the policy engine all k8s namespaces
func updatePolicyEngineWithNamespaces(pe *eval.PolicyEngine, clientset kubernetes.Interface) error {
	ctx, cancel := context.WithTimeout(context.Background(), pkgcommon.CtxTimeoutSeconds*time.Second)
	defer cancel()
	// get all namespaces
	nsList, apiErr := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if apiErr != nil {
		return apiErr
	}
	for i := range nsList.Items {
		ns := &nsList.Items[i]
		if err := pe.InsertObject(ns); err != nil {
			return err
		}
	}
	return nil
}

// updatePolicyEngineWithNetworkPolicies inserts to the policy engine all k8s network-policies
func updatePolicyEngineWithNetworkPolicies(pe *eval.PolicyEngine, clientset kubernetes.Interface) error {
	ctx, cancel := context.WithTimeout(context.Background(), pkgcommon.CtxTimeoutSeconds*time.Second)
	defer cancel()
	// get all netpols
	npList, apiErr := clientset.NetworkingV1().NetworkPolicies(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if apiErr != nil {
		return apiErr
	}
	for i := range npList.Items {
		if err := pe.InsertObject(&npList.Items[i]); err != nil {
			return err
		}
	}
	return nil
}

// updatePolicyEngineWithPods inserts to the policy engine all k8s pods
func updatePolicyEngineWithPods(pe *eval.PolicyEngine, clientset kubernetes.Interface) error {
	ctx, cancel := context.WithTimeout(context.Background(), pkgcommon.CtxTimeoutSeconds*time.Second)
	defer cancel()
	// get all pods
	podList, apiErr := clientset.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if apiErr != nil {
		return apiErr
	}
	for i := range podList.Items {
		if err := pe.InsertObject(&podList.Items[i]); err != nil {
			return err
		}
	}
	return nil
}

// ConnlistFromK8sCluster returns the allowed connections list from k8s cluster resources, and list of all peers names
// Deprecated
func (ca *ConnlistAnalyzer) ConnlistFromK8sCluster(clientset *kubernetes.Clientset) ([]Peer2PeerConnection, []Peer, error) {
	pe := eval.NewPolicyEngineWithOptions(ca.exposureAnalysis)

	// insert namespaces, network-policies and pods from k8s clientset
	// 1. insert namespaces from k8s clientset
	err := updatePolicyEngineWithNamespaces(pe, clientset)
	if err != nil {
		return nil, nil, err
	}

	// 2. insert network-policies from  k8s clientset
	err = updatePolicyEngineWithNetworkPolicies(pe, clientset)
	if err != nil {
		return nil, nil, err
	}

	// 3. insert pods from k8s clientset
	err = updatePolicyEngineWithPods(pe, clientset)
	if err != nil {
		return nil, nil, err
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
	focusConnStr := ""
	if ca.focusConnSet != nil {
		focusConnStr = ca.focusConnSet.String()
	}
	out, err := connsFormatter.writeOutput(conns, ca.exposureResult, ca.exposureAnalysis, ca.explain, focusConnStr, ca.primaryUdnNamespaces)
	if err != nil {
		ca.errors = append(ca.errors, newResultFormattingError(err))
		return "", err
	}
	return out, nil
}

// returns the relevant formatter for the analyzer's outputFormat
func (ca *ConnlistAnalyzer) getFormatter() (connsFormatter, error) {
	if err := output.ValidateOutputFormat(ca.outputFormat, ValidFormats); err != nil {
		return nil, err
	}
	switch ca.outputFormat {
	case output.JSONFormat:
		return &formatJSON{}, nil
	case output.TextFormat:
		return &formatText{}, nil
	case output.DOTFormat:
		return &formatDOT{ca.peersList}, nil
	case output.CSVFormat:
		return &formatCSV{}, nil
	case output.MDFormat:
		return &formatMD{}, nil
	case output.SVGFormat:
		return &formatSVG{ca.peersList}, nil
	default:
		return &formatText{}, nil
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////////////////
// internal type definitions below

// connection implements the Peer2PeerConnection interface
type connection struct {
	src                 Peer
	dst                 Peer
	allConnections      bool
	commonImplyingRules common.ImplyingRulesType // used for explainability, when allConnections is true
	protocolsAndPorts   map[v1.Protocol][]common.PortRange
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

func (c *connection) onlyDefaultRule() bool {
	return c.allConnections && len(c.protocolsAndPorts) == 0 && c.commonImplyingRules.OnlyDefaultRule()
}

func (c *connection) deniedCrossNetworksRule() bool {
	return !c.allConnections && len(c.protocolsAndPorts) == 0 && c.commonImplyingRules.CrossNetworkDenyRule()
}

// returns a *common.ConnectionSet from Peer2PeerConnection data
func GetConnectionSetFromP2PConnection(c Peer2PeerConnection) *common.ConnectionSet {
	protocolsToPortSetMap := make(map[v1.Protocol]*common.PortSet, len(c.ProtocolsAndPorts()))
	for protocol, portRangeArr := range c.ProtocolsAndPorts() {
		protocolsToPortSetMap[protocol] = common.MakePortSet(false)
		for _, p := range portRangeArr {
			augmentedRange := p.(*common.PortRangeData)
			// we cannot fill explainability data here, so we pass an empty rule name and an arbitrary direction (isIngress being true)
			protocolsToPortSetMap[protocol].AddPortRange(augmentedRange.Start(), augmentedRange.End(),
				augmentedRange.InSet(), "", "", true)
		}
	}
	connectionSet := &common.ConnectionSet{AllowAll: c.AllProtocolsAndPorts(), AllowedProtocols: protocolsToPortSetMap}
	return connectionSet
}

//////////////////////////////////////////////////////////////////////////////////////////////

func (ca *ConnlistAnalyzer) includePairOfWorkloads(pe *eval.PolicyEngine, src, dst Peer) bool {
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
	if ca.focusDirection == pkgcommon.IngressFocusDirection && !isPeerFocusWorkload(dst, ca.focusWorkloads) {
		return false
	}
	if ca.focusDirection == pkgcommon.EgressFocusDirection && !isPeerFocusWorkload(src, ca.focusWorkloads) {
		return false
	}
	// no focus-workloads or at least one of src/dst should be a focus workload,
	// Note that if ca.focusWorkloadPeer is not empty, the other peer must be a focusworkload-peer.
	// Note that if ca.focusDirection is defined; it is applied only to the focus-workloads (the check already done)
	return (isPeerFocusWorkload(src, ca.focusWorkloads) && ca.isPeerFocusWorkloadPeer(dst)) ||
		(isPeerFocusWorkload(dst, ca.focusWorkloads) && ca.isPeerFocusWorkloadPeer(src))
}

func (ca *ConnlistAnalyzer) includePairWithRepresentativePeer(pe *eval.PolicyEngine, src, dst Peer) bool {
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

func getPeerNsNameFormat(peer Peer) string {
	return types.NamespacedName{Namespace: peer.Namespace(), Name: peer.Name()}.String()
}

// isPeerFocusWorkload gets a peer and list of focus-workloads (or focus-workloads peers list);
// returns true if the focus-workloads list is empty (no focus-peers = each peer is included),
// or if the peer's name is in the focus-workload list
func isPeerFocusWorkload(peer Peer, focusWlsList []string) bool {
	if len(focusWlsList) == 0 {
		return true
	}
	for _, focusWl := range focusWlsList {
		if peer.Name() == focusWl || getPeerNsNameFormat(peer) == focusWl {
			return true
		}
	}
	return false
}

// isPeerFocusWorkloadPeer returns true if focusworkload-peer flag is not used (each peer matches),
// or if the input peer's name is equal to the focusworkload-peer (ca.focusWorkloadPeer)
// or if there are no focus-workloads (then the focusworkload-peer is ignored)
func (ca *ConnlistAnalyzer) isPeerFocusWorkloadPeer(peer Peer) bool {
	if len(ca.focusWorkloads) == 0 {
		return true // i.e. ignore focus-workload peers
	}
	return isPeerFocusWorkload(peer, ca.focusWorkloadPeers)
}

func convertEvalPeersToConnlistPeer(peers []eval.Peer) []Peer {
	res := make([]Peer, len(peers))
	for i, p := range peers {
		res[i] = p
	}
	return res
}

// getPeersForConnsComputation returns two slices of src and dst peers and a slice of workload peers.
// - srcPeers contains all workload peers from manifests + (if exposure-analysis) representative peers + disjoint ip-blocks
// from ingress policy rules
// - dstPeers contains all workload peers from manifests + (if exposure-analysis) representative peers + disjoint ip-blocks
// from egress policy rules
// - peers is list of workload peers from manifests
func (ca *ConnlistAnalyzer) getPeersForConnsComputation(pe *eval.PolicyEngine) (srcPeers, dstPeers, peers []Peer, err error) {
	// get ip-block peers (src ip-block and dst ip-blocks and disjoint of both) extracted from policy rules
	srcIpbList, dstIpbList, _, err := pe.GetIPBlockPeersLists()
	if err != nil {
		ca.errors = append(ca.errors, newResourceEvaluationError(err))
		return nil, nil, nil, err
	}
	// initiate results slices with IpBlock peers (peers are  converted []connlist.Peer list to be used in connlist pkg and returned)
	srcPeers = convertEvalPeersToConnlistPeer(srcIpbList)
	dstPeers = convertEvalPeersToConnlistPeer(dstIpbList)

	// get workload peers - peers from manifests
	peerList, err := pe.GetWorkloadPeersList()
	if err != nil {
		ca.errors = append(ca.errors, newResourceEvaluationError(err))
		return nil, nil, nil, err
	}
	// represent peerList as []connlist.Peer list to be used and returned by connlist pkg
	workloadPeers := convertEvalPeersToConnlistPeer(peerList)
	// append workload peers to results slices
	srcPeers = append(srcPeers, workloadPeers...)
	dstPeers = append(dstPeers, workloadPeers...)
	peers = workloadPeers

	// if exposure-analysis is on get representative peers and append to src and dst peers slices
	if ca.exposureAnalysis {
		representativePeers := convertEvalPeersToConnlistPeer(pe.GetRepresentativePeersList())
		srcPeers = append(srcPeers, representativePeers...)
		dstPeers = append(dstPeers, representativePeers...)
	}

	// update the ca.peersList from workload peers list (used for updating dot/svg outputs with all workloads from manifests)
	ca.peersList = make([]Peer, 0, len(peerList))
	for _, p := range peerList {
		if isPeerFocusWorkload(p, ca.focusWorkloads) || (len(ca.focusWorkloadPeers) != 0 && ca.isPeerFocusWorkloadPeer(p)) {
			ca.peersList = append(ca.peersList, p)
		}
	}

	return srcPeers, dstPeers, peers, nil
}

// flagsValidation validates input flags values or format
func (ca *ConnlistAnalyzer) flagsValidation() error {
	if err := ca.validateFocusDirectionValue(); err != nil {
		return err
	}
	if err := ca.validateExplainOnlyValue(); err != nil {
		return err
	}
	return ca.validateFocusConnFormatAndValue()
}

// getConnectionsList returns connections list from PolicyEngine and ingressAnalyzer objects
// if the exposure-analysis option is on, also computes and updates the exposure-analysis results
func (ca *ConnlistAnalyzer) getConnectionsList(pe *eval.PolicyEngine, ia *ingressanalyzer.IngressAnalyzer) ([]Peer2PeerConnection,
	[]Peer, error) {
	// validate input flags values
	if err := ca.flagsValidation(); err != nil {
		return nil, nil, err
	}

	connsRes := make([]Peer2PeerConnection, 0)
	if !pe.HasPodPeers() {
		return connsRes, []Peer{}, nil
	}

	// srcPeers are : all workload peers from manifests + (if exposure-analysis) representative peers + disjoint ip-blocks
	// from ingress policy rules
	// dstPeers are : all workload peers from manifests + (if exposure-analysis) representative peers + disjoint ip-blocks
	// from egress policy rules
	// srcPeers and dstPeers are used to compute allowed conns between peers (to be sent to ca.getConnectionsBetweenPeers)
	// peers is the list of workload peers from manifests (to be returned by connlist API)
	srcPeers, dstPeers, peers, err := ca.getPeersForConnsComputation(pe)
	if err != nil {
		return nil, nil, err
	}

	excludeIngressAnalysis := (ia == nil || ia.IsEmpty())
	// check if a connlist may be produced for input ca.focusWorkloads and ca.focusWorkloadPeer (existence if given)
	// 1. if focusworkload flag is used, check for the existence of the given focus-workloads and
	// return if all the focus-workloads do not exist (not possible to produce a connlist)
	if !ca.checkFocusWorkloadsExistence(ca.focusWorkloads, excludeIngressAnalysis) {
		return nil, nil, nil
	}
	// 2. if there are existing peers in ca.focusWorkloads; check for the ca.focusWorkloadPeers too and
	// return if all the ca.focusWorkloadPeers do not exist (no conns to filter between given inputs)
	if len(ca.focusWorkloads) > 0 && !ca.checkFocusWorkloadsExistence(ca.focusWorkloadPeers, excludeIngressAnalysis) {
		return nil, nil, nil
	}

	// compute connections between peers based on pe analysis of network policies
	// if exposure-analysis is on, also compute and return the exposures-map
	peersAllowedConns, exposureMaps, err := ca.getConnectionsBetweenPeers(pe, srcPeers, dstPeers)
	if err != nil {
		ca.errors = append(ca.errors, newResourceEvaluationError(err))
		return nil, nil, err
	}
	// log warnings that were raised by the policies during computing the allowed conns between all peers
	// note that this ensures any warning is printed only once + all relevant warnings are raised.
	// the decision if to print the warnings to the logger is determined by the logger's verbosity - handled by the logger
	policiesWarns := pe.LogPolicyEngineWarnings()
	// policiesWarns already printed to the logger, add them also to the ca.Errors API system
	for _, warn := range policiesWarns {
		ca.errors = append(ca.errors, newConnlistAnalyzerWarning(errors.New(warn)))
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

	if len(ca.focusWorkloads) == 0 && len(peersAllowedConns) == 0 {
		ca.logWarning(alerts.NoAllowedConnsWarning)
	}

	return connsRes, peers, nil
}

// checkFocusWorkloadsExistence checks if the peers in the given focus-workloads (or focus workload-peers) list exist;
// returns false if none of the peers in the list exist
func (ca *ConnlistAnalyzer) checkFocusWorkloadsExistence(focusWlsList []string, excludeIngressAnalysis bool) bool {
	if len(focusWlsList) == 0 {
		return true // no focus-workloads means no need to filter the connlist, return true to proceed in connlist generating
	}
	// if ca.focusWorkloads is not empty, for each focus-workload: check if it exists in the peers before proceeding
	cnt := 0 // count number of the focus-workloads which does not exist
	for _, focusWl := range focusWlsList {
		existFocusWorkload, warningMsg := ca.existsFocusWorkload(focusWl, excludeIngressAnalysis)
		if !existFocusWorkload {
			cnt++
			ca.logWarning(warningMsg)
		}
	}
	// if all focus-workloads do not exist: nothing to do (empty connlist); return
	if cnt != 0 && cnt == len(focusWlsList) {
		ca.logWarning(alerts.EmptyConnListErrStr)
		return false
	}
	return true
}

// existsFocusWorkload checks if the provided focus workload is ingress-controller
// or if it exists in the peers list from the parsed resources
// if not returns a suitable warning message
func (ca *ConnlistAnalyzer) existsFocusWorkload(focusWorkload string, excludeIngressAnalysis bool) (existFocusWorkload bool,
	warning string) {
	if focusWorkload == common.IngressPodName {
		if excludeIngressAnalysis { // if the ingress-analyzer is empty,
			// then no routes/k8s-ingress objects -> ingress-controller pod will not be added
			return false, alerts.NoIngressSourcesErrStr
		}
		return true, ""
	}

	// check if the given focus-workload is in the peers
	for _, peer := range ca.peersList {
		if peer.Name() == focusWorkload || getPeerNsNameFormat(peer) == focusWorkload {
			return true, ""
		}
	}
	return false, alerts.WorkloadDoesNotExistErrStr(focusWorkload)
}

// getConnectionsBetweenPeers returns connections list from PolicyEngine object
// and exposures-map containing the exposed peers data if the exposure-analysis is on , else empty map
//
//gocyclo:ignore
func (ca *ConnlistAnalyzer) getConnectionsBetweenPeers(pe *eval.PolicyEngine, srcPeers, dstPeers []Peer) ([]Peer2PeerConnection,
	*exposureMaps, error) {
	connsRes := make([]Peer2PeerConnection, 0)
	exposureMaps := &exposureMaps{
		ingressExposureMap: map[Peer]*peerXgressExposureData{},
		egressExposureMap:  map[Peer]*peerXgressExposureData{},
	}
	// for exposure-analysis use: sets for marking peer checked for ingress/egress exposure to entire cluster data once
	ingressSet := make(map[Peer]bool, 0)
	egressSet := make(map[Peer]bool, 0)

	for i := range srcPeers {
		srcPeer := srcPeers[i]
		for j := range dstPeers {
			dstPeer := dstPeers[j]
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
			// skip empty connections when running without explainability or with explain-only allow mode
			// unless one of the peers is representative
			// if one of the peers is representative, we keep this empty exposure connection to check later if it is
			// an exception to an entire-cluster exposure.
			// e.g if the pod is exposed to entire-cluster but not exposed to this representative-peer (because of a deny rule),
			// we need to include this "No connection" in the exposure-output.
			// see example : "tests/exposure_test_with_anp_9"
			if allowedConnections.IsEmpty() && !pe.IsRepresentativePeer(srcPeer) && !pe.IsRepresentativePeer(dstPeer) &&
				(!ca.explain || ca.explainOnly == pkgcommon.ExplainOnlyAllow) {
				continue
			}
			// skip non-empty connections when running on explain-only deny mode (i.e `--explain` and `--explain-only` deny are used)
			if !allowedConnections.IsEmpty() && ca.explainOnly == pkgcommon.ExplainOnlyDeny && ca.focusConnSet == nil {
				continue
			}
			// - if focus conns is not empty and not explain mode, skip the connections if focus conn is not contained in the allowed conns
			// - Note that: in explain mode: we don't skip since allowed-conns contains also explanation data on the denied data (focus-conn);
			if !ca.explain && ca.focusConnection != "" && !ca.focusConnSet.ContainedIn(allowedConnections) {
				continue
			}
			connlistAllowedConnections := allowedConnections
			if ca.focusConnSet != nil { // only focus connection data is meaningful in this case
				connlistAllowedConnections, err = ca.getFocusConnSetWithDataFromAllowedConns(allowedConnections)
				if err != nil {
					return nil, nil, err
				}
			}
			if connlistAllowedConnections == nil { // focus conn data is not relevant for the analysis
				continue
			}
			p2pConnection, err := ca.getP2PConnOrUpdateExposureConn(pe, connlistAllowedConnections, srcPeer, dstPeer, exposureMaps)
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
	ingressControllerPod, err := pe.AddPodByNameAndNamespace(common.IngressPodName, common.IngressPodNamespace)
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
		peConn.RemoveDefaultRule(true)
		peerAndConn.ConnSet.Intersection(peConn)
		peerAndConn.ConnSet.SetExplResult(true)
		if peerAndConn.ConnSet.IsEmpty() {
			ca.warnBlockedIngress(peerStr, peerAndConn.IngressObjects)
			continue
		}
		allowedConn := peerAndConn.ConnSet
		if ca.focusConnSet != nil {
			allowedConn, err = ca.getFocusConnSetWithDataFromAllowedConns(peerAndConn.ConnSet) // if focus-conn is used,
			//  only the focus connection is meaningful
			if err != nil {
				return nil, err
			}
			if allowedConn == nil || (!ca.explain && !ca.focusConnSet.ContainedIn(peerAndConn.ConnSet)) {
				continue
			}
		}
		p2pConnection := createConnectionObject(allowedConn, ingressControllerPod, peerAndConn.Peer)
		res = append(res, p2pConnection)
	}
	return res, nil
}

func (ca *ConnlistAnalyzer) warnBlockedIngress(peerStr string, ingressObjects map[string][]string) {
	objKind := ""
	objName := ""
	if len(ingressObjects[parser.Ingress]) > 0 {
		objKind = "K8s-Ingress"
		objName = ingressObjects[parser.Ingress][0]
	} else if len(ingressObjects[parser.Route]) > 0 {
		objKind = "Route"
		objName = ingressObjects[parser.Route][0]
	}
	warningMsg := alerts.BlockedIngressWarning(objKind, objName, peerStr)
	ca.logWarning(warningMsg)
}

func (ca *ConnlistAnalyzer) logWarning(msg string) {
	if !ca.muteErrsAndWarns {
		ca.logger.Warnf(msg)
	}
	// appending the warning to the ca.errors (used by ca api func Errors())
	ca.errors = append(ca.errors, newConnlistAnalyzerWarning(errors.New(msg)))
}

// getP2PConnOrUpdateExposureConn if the given connection is between two peers from the parsed resources,
// or between a real peer and IP-block, returns it as P2P connection object;
// otherwise the connection belongs to exposure-analysis, will be added to the provided exposure-map.
func (ca *ConnlistAnalyzer) getP2PConnOrUpdateExposureConn(pe *eval.PolicyEngine, allowedConnections common.Connection,
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
	err := exposureMaps.addConnToExposureMap(pe, allowedConnections, src, dst, isIngress, ca.focusConnSet)
	return nil, err
}

// helper function - returns a connection object from the given fields
func createConnectionObject(allowedConnections common.Connection, src, dst Peer) *connection {
	return &connection{
		src:                 src,
		dst:                 dst,
		allConnections:      allowedConnections.IsAllConnections(),
		commonImplyingRules: allowedConnections.(*common.ConnectionSet).CommonImplyingRules,
		protocolsAndPorts:   allowedConnections.ProtocolsAndPortsMap(true),
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
	if ca.shouldAddPeerGeneralExposureData(pe, src, egressSet) && (ca.focusDirection == "" ||
		ca.focusDirection == pkgcommon.EgressFocusDirection) {
		err = exMaps.addPeerGeneralExposure(pe, src, false, ca.focusConnSet)
		if err != nil {
			return err
		}
	}
	egressSet[src] = true
	// 2. only on first time : add general exposure data for the dst peer (on ingress)
	if ca.shouldAddPeerGeneralExposureData(pe, dst, ingressSet) && (ca.focusDirection == "" ||
		ca.focusDirection == pkgcommon.IngressFocusDirection) {
		err = exMaps.addPeerGeneralExposure(pe, dst, true, ca.focusConnSet)
	}
	ingressSet[dst] = true
	return err
}

// shouldAddPeerGeneralExposureData returns whether should add given peer's general
// exposure data to the exposure results.
// returns true if all of the following are true:
// - the peer is not IP type
// - the peer is not representative peer
// - focus-workload flag is not used or the peer is a focus-workload
// - it is first time the peer is visited
func (ca *ConnlistAnalyzer) shouldAddPeerGeneralExposureData(pe *eval.PolicyEngine, peer Peer, xgressSet map[Peer]bool) bool {
	return !peer.IsPeerIPType() && !pe.IsRepresentativePeer(peer) && !xgressSet[peer] && isPeerFocusWorkload(peer, ca.focusWorkloads)
}

// getFocusConnSetWithDataFromAllowedConns returns connection set with all relevant data of the focus-connection from allowed-connections
// if ca.explain is off, then returns ca.focusConnSet (already checked that it is contained in allowedConns);
// otherwise, returns a connectionSet with same protocol-port of the focus connection-set and relevant explanation data from allowedConns;
// note that: this function is called only if `ca.focusConnection (focus-conn)` is not empty
// this func considers also explain-only flag if used
func (ca *ConnlistAnalyzer) getFocusConnSetWithDataFromAllowedConns(allowedConns *common.ConnectionSet) (fc *common.ConnectionSet,
	err error) {
	if !ca.explain {
		return ca.focusConnSet, nil
	}
	// else : explain is on
	focusConnSetWithExp, allowedFlag, err := common.GetFocusConnSetWithExplainabilityFromAllowedConnSet(allowedConns, ca.focusConnSet)
	if ca.explainOnly == pkgcommon.ExplainOnlyAllow && !allowedFlag {
		return nil, nil // the focus conn is denied - nothing to display
	}
	if ca.explainOnly == pkgcommon.ExplainOnlyDeny && allowedFlag {
		return nil, nil // focus conn is allowed - nothing to display
	}
	return focusConnSetWithExp, err
}
