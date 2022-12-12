package connlist

import (
	"context"
	"fmt"

	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	v1 "k8s.io/api/core/v1"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/scan"
)

const (
	connsAndPortRangeSeparator = ","
)

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

// FromYAMLManifests returns the allowed connections list from input YAML manifests
func FromYAMLManifests(manifests []string) ([]Peer2PeerConnection, error) {
	objectsList, err := scan.YAMLDocumentsToObjectsList(manifests)
	if err != nil {
		return nil, err
	}
	pe := eval.NewPolicyEngine()
	for _, obj := range objectsList {
		if obj.Kind == scan.Pod {
			err = pe.UpsertObject(obj.Pod)
		} else if obj.Kind == scan.Namespace {
			err = pe.UpsertObject(obj.Namespace)
		} else if obj.Kind == scan.Networkpolicy {
			err = pe.UpsertObject(obj.Networkpolicy)
		}
		if err != nil {
			return nil, err
		}
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

	// get all namespaces
	nsList, apierr := clientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
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
	podList, apierr := clientset.CoreV1().Pods(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{})
	if apierr != nil {
		return nil, apierr
	}
	for i := range podList.Items {
		if err := pe.UpsertObject(&podList.Items[i]); err != nil {
			return nil, err
		}
	}

	// get all netpols
	npList, apierr := clientset.NetworkingV1().NetworkPolicies(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{})
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
	peerList, err := pe.GetPeersList() // pods and ip blocks
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
			allowedConnections, err := pe.AllAllowedConnectionsBetweenPeers(srcPeer, dstPeer)
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
func ConnectionsListToString(conns []Peer2PeerConnection) string {
	connLines := make([]string, len(conns))
	for i := range conns {
		connLines[i] = conns[i].String()
	}
	sort.Strings(connLines)
	return strings.Join(connLines, "\n")
}

// get string representation for a list of port ranges
func portsString(ports []eval.PortRange) string {
	portsStr := make([]string, len(ports))
	for i := range ports {
		portsStr[i] = ports[i].String()
	}
	return strings.Join(portsStr, connsAndPortRangeSeparator)
}
