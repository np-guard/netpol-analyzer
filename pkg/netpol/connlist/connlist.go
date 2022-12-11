package connlist

import (
	"context"
	"fmt"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/scan"
)

const (
	connsAndPortRangeSeparator = ","
)

// Peer2PeerConnection encapsulates the allowed connectivity result between two peers.
type Peer2PeerConnection interface {
	// Src returns the source peer
	Src() Peer
	// Dst returns the destination peer
	Dst() Peer
	// AllProtocolsAndPorts returns true if all ports are allowed for all protocols
	AllProtocolsAndPorts() bool
	// ProtocolsAndPorts returns the set of allowed connections
	ProtocolsAndPorts() map[v1.Protocol][]PortRange
	// String returns a string representation of the connection object
	String() string
}

// Peer can either represent a Pod or an IP address
type Peer interface {
	// GetNamespace returns a pod's namespace in case the peer is a pod, else it returns an empty string
	GetNamespace() string
	// GetName returns a pod's name in case the peer is a pod, else it returns an empty string
	GetName() string
	// GetIP returns an IP address string in case peer is IP address, else it returns an empty string
	GetIP() string
	// String returns a string representation of the Peer object
	String() string
}

// PortRange describes a port or a range of ports for allowed traffic
// If start port equals end port, it represents a single port
type PortRange interface {
	// Start is the start port
	Start() int64
	// End is the end port
	End() int64
	// String returns a string representation of the PortRange object
	String() string
}

//////////////////////////////////////////////////////////////////////////////////////////////
// internal type definitions below

// connection implements the Peer2PeerConnection interface
type connection struct {
	src               peer
	dst               peer
	allConnections    bool
	protocolsAndPorts map[v1.Protocol][]portRange
}

func (c connection) Src() Peer {
	return c.src
}
func (c connection) Dst() Peer {
	return c.dst
}
func (c connection) AllProtocolsAndPorts() bool {
	return c.allConnections
}
func (c connection) ProtocolsAndPorts() map[v1.Protocol][]PortRange {
	res := make(map[v1.Protocol][]PortRange, len(c.protocolsAndPorts))
	for protocol, ports := range c.protocolsAndPorts {
		res[protocol] = make([]PortRange, len(ports))
		for i := range ports {
			res[protocol][i] = ports[i]
		}
	}
	return res
}

// peer implements the Peer interface
type peer struct {
	namespace string
	name      string
	ip        string
}

func (p peer) GetNamespace() string {
	return p.namespace
}

func (p peer) GetName() string {
	return p.name
}

func (p peer) GetIP() string {
	return p.ip
}

func (p peer) String() string {
	if p.GetIP() != "" {
		return p.GetIP()
	}
	return types.NamespacedName{Name: p.GetName(), Namespace: p.GetNamespace()}.String()
}

// portRange implements the PortRange interface
type portRange struct {
	start int64
	end   int64
}

func (pr portRange) Start() int64 {
	return pr.start
}
func (pr portRange) End() int64 {
	return pr.end
}

//////////////////////////////////////////////////////////////////////////////////////////////

// FromDir returns the allowed connections list from dir path resources
func FromDir(dirPath string) ([]Peer2PeerConnection, error) {
	pe := eval.NewPolicyEngine()
	// get all resources from dir
	objectsList, err := scan.FilesToObjectsList(dirPath)
	if err != nil {
		return nil, err
	}
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
	res := make([]Peer2PeerConnection, 0)
	peerList, err := pe.GetPeersList() // pods and ip blocks
	if err != nil {
		return nil, err
	}
	for i := range peerList {
		for j := range peerList {
			srcPeer := peerList[i]
			dstPeer := peerList[j]
			if eval.IsPeerIPType(srcPeer) && eval.IsPeerIPType(dstPeer) {
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
			protocolsMap := allowedConnections.GetProtocolsAndPortsMap()
			connection := connection{
				src:               peer{name: srcPeer.Name(), namespace: srcPeer.NamespaceStr(), ip: srcPeer.IP()},
				dst:               peer{name: dstPeer.Name(), namespace: dstPeer.NamespaceStr(), ip: dstPeer.IP()},
				allConnections:    allowedConnections.AllowAll,
				protocolsAndPorts: make(map[v1.Protocol][]portRange, len(protocolsMap)),
			}
			// convert each port range (list) to connlist.Port
			for protocol, ports := range protocolsMap {
				connection.protocolsAndPorts[protocol] = make([]portRange, len(ports))
				for i := range ports {
					startPort, endPort := ports[i][0], ports[i][1]
					port := portRange{start: startPort, end: endPort}
					connection.protocolsAndPorts[protocol][i] = port
				}
			}
			res = append(res, connection)
		}
	}
	return res, nil
}

// return a string representation for a Peer2PeerConnection object
func (pc connection) String() string {
	var connStr string
	if pc.AllProtocolsAndPorts() {
		connStr = "All Connections"
	} else if len(pc.ProtocolsAndPorts()) == 0 {
		connStr = "No Connections"
	} else {
		connStrings := make([]string, len(pc.ProtocolsAndPorts()))
		index := 0
		for protocol, ports := range pc.ProtocolsAndPorts() {
			connStrings[index] = string(protocol) + " " + portsString(ports)
			index++
		}
		sort.Strings(connStrings)
		connStr = strings.Join(connStrings, connsAndPortRangeSeparator)
	}
	return fmt.Sprintf("%s => %s : %s", pc.Src().String(), pc.Dst().String(), connStr)
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

// return a string representation for a Port object
func (p portRange) String() string {
	if p.End() != p.Start() {
		return fmt.Sprintf("%d-%d", p.Start(), p.End())
	}
	return fmt.Sprintf("%d", p.Start())
}

// get string representation for a list of port values
func portsString(ports []PortRange) string {
	portsStr := make([]string, len(ports))
	for i := range ports {
		portsStr[i] = ports[i].String()
	}
	return strings.Join(portsStr, connsAndPortRangeSeparator)
}
