package connlist

import (
	"context"
	"fmt"
	"time"

	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	v1 "k8s.io/api/core/v1"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/scan"
)

// The connlist package allows producing a k8s connectivity report based on network policies.
// It lists the set of allowed connections between each pair of peers (k8s workloads or ip-blocks).
// The resources can be extracted from a directory containing YAML manifests, or from a k8s cluster.

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

type OutputFormat int

const (
	Txt OutputFormat = iota
	Dot
)

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
	connStr := getProtocolsAndPortsStr(c)
	return fmt.Sprintf("%s => %s : %s", c.Src().String(), c.Dst().String(), connStr)
}

func getProtocolsAndPortsStr(c Peer2PeerConnection) string {
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
	return connStr
}

//////////////////////////////////////////////////////////////////////////////////////////////

// FromYAMLManifests returns the allowed connections list from input YAML manifests
func FromYAMLManifests(manifests []string) ([]Peer2PeerConnection, error) {
	objectsList, err := scan.YAMLDocumentsToObjectsList(manifests)
	if err != nil {
		return nil, err
	}
	pe, err := eval.NewPolicyEngineWithObjects(objectsList)
	if err != nil {
		return nil, err
	}
	return getConnectionsList(pe)
}

// FromDir returns the allowed connections list from dir path resources
// walkFn : for customizing directory scan
func FromDir(dirPath string, walkFn scan.WalkFunction) ([]Peer2PeerConnection, error) {
	manifests := scan.GetYAMLDocumentsFromPath(dirPath, walkFn)
	return FromYAMLManifests(manifests)
}

// FromK8sCluster returns the allowed connections list from k8s cluster resources
func FromK8sCluster(clientset *kubernetes.Clientset) ([]Peer2PeerConnection, error) {
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
	return getConnectionsList(pe)
}

// getConnectionsList returns connections list from PolicyEngine object
func getConnectionsList(pe *eval.PolicyEngine) ([]Peer2PeerConnection, error) {
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
			if srcPeer.IsPeerIPType() && dstPeer.IsPeerIPType() {
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

// get string of connections from list of Peer2PeerConnection objects
func ConnectionsListToString(conns []Peer2PeerConnection, outFormat OutputFormat) string {
	switch outFormat {
	case Txt:
		return produceTxtOutput(conns)
	case Dot:
		return produceDotOutput(conns)
	}
	return ""
}

// get string representation for a list of port ranges
func portsString(ports []eval.PortRange) string {
	portsStr := make([]string, len(ports))
	for i := range ports {
		portsStr[i] = ports[i].String()
	}
	return strings.Join(portsStr, connsAndPortRangeSeparator)
}

func getPeerLine(peer eval.Peer) string {
	var peerColor string
	if peer.IsPeerIPType() {
		peerColor = "red2"
	} else {
		peerColor = "blue"
	}
	peerName := peer.String()
	return fmt.Sprintf("\t\"%s\" [label=\"%s\" color=\"%s\" fontcolor=\"%s\"]\n", peerName, peerName, peerColor, peerColor)
}

func produceTxtOutput(conns []Peer2PeerConnection) string {
	connLines := make([]string, len(conns))
	for i := range conns {
		connLines[i] = conns[i].String()
	}
	sort.Strings(connLines)
	newlineChar := fmt.Sprintln("")
	return strings.Join(connLines, newlineChar)
}

func produceDotOutput(connsList []Peer2PeerConnection) string {
	edgeLines := make([]string, len(connsList))
	peerLines := make(map[string]string, 0)
	for index := range connsList {
		conn := connsList[index]
		src := conn.Src().String()
		dst := conn.Dst().String()
		connSet := getProtocolsAndPortsStr(conn)
		edgeLines[index] = fmt.Sprintf("\t\"%s\" -> \"%s\" [label=\"%s\" color=\"gold2\" fontcolor=\"darkgreen\"]\n", src, dst, connSet)
		if _, ok := peerLines[src]; !ok {
			peerLines[src] = getPeerLine(conn.Src())
		}
		if _, ok := peerLines[dst]; !ok {
			peerLines[dst] = getPeerLine(conn.Dst())
		}
	}
	res := "digraph {\n"
	for _, peerLine := range peerLines {
		res += peerLine
	}
	for _, edgeLine := range edgeLines {
		res += edgeLine
	}
	res += "}\n"
	return res
}
