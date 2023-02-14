// The connlist package of netpol-analyzer allows producing a k8s connectivity report based on network policies.
// It lists the set of allowed connections between each pair of peers (k8s workloads or ip-blocks).
// The resources can be extracted from a directory containing YAML manifests, or from a k8s cluster.
// For more information, see https://github.com/np-guard/netpol-analyzer.
package connlist

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	v1 "k8s.io/api/core/v1"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/logger"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/scan"
)

// ConnlistError holds information about a single error/warning that occurred during
// the parsing and connectivity analysis of k8s-app with network policies
type ConnlistError interface {
	IsFatal() bool
	IsSevere() bool
	Error() error
	Location() string
}

// A ConnlistAnalyzer provides API to recursively scan a directory for Kubernetes resources including network policies,
// and get the list of permitted connectivity between the workloads of the K8s application managed in this directory.
type ConnlistAnalyzer struct {
	logger        logger.Logger
	stopOnError   bool
	errors        []ConnlistError
	walkFn        scan.WalkFunction
	scanner       *scan.ResourcesScanner
	focusWorkload string
}

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

// NewConnlistAnalyzer creates a new instance of ConnlistAnalyzer, and applies the provided functional options.
func NewConnlistAnalyzer(options ...ConnlistAnalyzerOption) *ConnlistAnalyzer {
	// object with default behavior options
	ca := &ConnlistAnalyzer{
		logger:      logger.NewDefaultLogger(),
		stopOnError: false,
		errors:      []ConnlistError{},
		walkFn:      filepath.WalkDir,
	}
	for _, o := range options {
		o(ca)
	}
	ca.scanner = scan.NewResourcesScanner(ca.logger, ca.stopOnError, ca.walkFn)
	return ca
}

// Errors returns a slice of FileProcessingError with all warnings and errors encountered during processing.
func (ca *ConnlistAnalyzer) Errors() []ConnlistError {
	return ca.errors
}

// return err object if it is fatal or severe with flag stopOnError
func (ca *ConnlistAnalyzer) stopProcessing() error {
	for idx := range ca.errors {
		if ca.errors[idx].IsFatal() || ca.stopOnError && ca.errors[idx].IsSevere() {
			return ca.errors[idx].Error()
		}
	}
	return nil
}

// ConnlistFromDirPath returns the allowed connections list from dir path containing k8s resources
func (ca *ConnlistAnalyzer) ConnlistFromDirPath(dirPath string) ([]Peer2PeerConnection, error) {
	objectsList, processingErrs := ca.scanner.FilesToObjectsList(dirPath)
	for i := range processingErrs {
		ca.errors = append(ca.errors, &processingErrs[i])
	}

	if err := ca.stopProcessing(); err != nil {
		return nil, err
	}
	return ca.connslistFromParsedResources(objectsList)
}

// ConnlistFromYAMLManifests returns the allowed connections list from input YAML manifests
func (ca *ConnlistAnalyzer) ConnlistFromYAMLManifests(manifests []scan.YAMLDocumentIntf) ([]Peer2PeerConnection, error) {
	objectsList, processingErrs := ca.scanner.YAMLDocumentsToObjectsList(manifests)
	for i := range processingErrs {
		ca.errors = append(ca.errors, &processingErrs[i])
	}

	if err := ca.stopProcessing(); err != nil {
		return nil, err
	}

	return ca.connslistFromParsedResources(objectsList)
}

func (ca *ConnlistAnalyzer) connslistFromParsedResources(objectsList []scan.K8sObject) ([]Peer2PeerConnection, error) {
	// TODO: do we need logger in policyEngine?
	pe, err := eval.NewPolicyEngineWithObjects(objectsList)
	if err != nil {
		return nil, err
	}
	return ca.getConnectionsList(pe)
}

// ConnlistFromK8sCluster returns the allowed connections list from k8s cluster resources
func (ca *ConnlistAnalyzer) ConnlistFromK8sCluster(clientset *kubernetes.Clientset) ([]Peer2PeerConnection, error) {
	pe := eval.NewPolicyEngine()

	// get all resources from k8s cluster

	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeoutSeconds*time.Second)
	defer cancel()

	// get all namespaces
	nsList, apierr := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if apierr != nil {
		return nil, apierr
	}
	for i := range nsList.Items {
		ns := &nsList.Items[i]
		if err := pe.UpsertObject(ns); err != nil {
			return nil, err
		}
	}

	// get all pods
	podList, apierr := clientset.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if apierr != nil {
		return nil, apierr
	}
	for i := range podList.Items {
		if err := pe.UpsertObject(&podList.Items[i]); err != nil {
			return nil, err
		}
	}

	// get all netpols
	npList, apierr := clientset.NetworkingV1().NetworkPolicies(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if apierr != nil {
		return nil, apierr
	}
	for i := range npList.Items {
		if err := pe.UpsertObject(&npList.Items[i]); err != nil {
			return nil, err
		}
	}
	return ca.getConnectionsList(pe)
}

// ConnectionsListToString returns a string of connections from list of Peer2PeerConnection objects
func (ca *ConnlistAnalyzer) ConnectionsListToString(conns []Peer2PeerConnection) string {
	connLines := make([]string, len(conns))
	for i := range conns {
		connLines[i] = conns[i].String()
	}
	sort.Strings(connLines)
	newlineChar := fmt.Sprintln("")
	return strings.Join(connLines, newlineChar)
}

//////////////////////////////////////////////////////////////////////////////////////////////

// Peer2PeerConnection encapsulates the allowed connectivity result between two peers.
type Peer2PeerConnection interface {
	// Src returns the source peer
	Src() eval.Peer
	// Dst returns the destination peer
	Dst() eval.Peer
	// AllProtocolsAndPorts returns true if all ports are allowed for all protocols
	AllProtocolsAndPorts() bool
	// ProtocolsAndPorts returns the set of allowed connections
	ProtocolsAndPorts() map[v1.Protocol][]eval.PortRange
	// String returns a string representation of the connection object
	String() string
}

//////////////////////////////////////////////////////////////////////////////////////////////
// internal type definitions below

const (
	connsAndPortRangeSeparator = ","
	ctxTimeoutSeconds          = 3
)

// connection implements the Peer2PeerConnection interface
type connection struct {
	src               eval.Peer
	dst               eval.Peer
	allConnections    bool
	protocolsAndPorts map[v1.Protocol][]eval.PortRange
}

func (c *connection) Src() eval.Peer {
	return c.src
}
func (c *connection) Dst() eval.Peer {
	return c.dst
}
func (c *connection) AllProtocolsAndPorts() bool {
	return c.allConnections
}
func (c *connection) ProtocolsAndPorts() map[v1.Protocol][]eval.PortRange {
	return c.protocolsAndPorts
}

// return a string representation for a connection object
func (c *connection) String() string {
	var connStr string
	if c.AllProtocolsAndPorts() {
		connStr = "All Connections"
	} else if len(c.ProtocolsAndPorts()) == 0 {
		connStr = "No Connections"
	} else {
		connStrings := make([]string, len(c.ProtocolsAndPorts()))
		index := 0
		for protocol, ports := range c.ProtocolsAndPorts() {
			connStrings[index] = string(protocol) + " " + portsString(ports)
			index++
		}
		sort.Strings(connStrings)
		connStr = strings.Join(connStrings, connsAndPortRangeSeparator)
	}
	return fmt.Sprintf("%s => %s : %s", c.Src().String(), c.Dst().String(), connStr)
}

//////////////////////////////////////////////////////////////////////////////////////////////

func (ca *ConnlistAnalyzer) includePairOfWorkloads(src, dst eval.Peer) bool {
	if src.IsPeerIPType() && dst.IsPeerIPType() {
		return false
	}
	if ca.focusWorkload == "" {
		return true
	}
	// at least one of src/dst should be the focus workload
	if !src.IsPeerIPType() && src.Name() == ca.focusWorkload {
		return true
	}
	if !dst.IsPeerIPType() && dst.Name() == ca.focusWorkload {
		return true
	}
	return false
}

// getConnectionsList returns connections list from PolicyEngine object
func (ca *ConnlistAnalyzer) getConnectionsList(pe *eval.PolicyEngine) ([]Peer2PeerConnection, error) {
	if !pe.HasPodPeers() {
		return nil, errors.New("cannot produce connectivity list without k8s workloads")
	}

	// get workload peers and ip blocks
	peerList, err := pe.GetPeersList()
	if err != nil {
		return nil, err
	}
	res := make([]Peer2PeerConnection, 0)
	for i := range peerList {
		for j := range peerList {
			srcPeer := peerList[i]
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
			connectionObj := &connection{
				src:               srcPeer,
				dst:               dstPeer,
				allConnections:    allowedConnections.AllConnections(),
				protocolsAndPorts: allowedConnections.ProtocolsAndPortsMap(),
			}
			res = append(res, connectionObj)
		}
	}
	return res, nil
}

// get string representation for a list of port ranges
func portsString(ports []eval.PortRange) string {
	portsStr := make([]string, len(ports))
	for i := range ports {
		portsStr[i] = ports[i].String()
	}
	return strings.Join(portsStr, connsAndPortRangeSeparator)
}
