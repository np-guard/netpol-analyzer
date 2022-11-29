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
	separator = ","
)

// Peer2PeerConnection encapsulates the allowed connectivity result between two peers.
type Peer2PeerConnection struct {
	// Src is the source peer. It can be a pod name (in the form of namespace/name) or an ip address.
	Src string
	// Dst is the destination peer. It can be a pod name (in the form of namespace/name) or an ip address.
	Dst string
	// AllProtocolsAndPorts is used when all ports are allowed for all protocols.
	// if set true then ProtocolsAndPorts is empty.
	// if false then allowed connections is according to ProtocolsAndPorts value.
	AllProtocolsAndPorts bool
	// ProtocolsAndPorts encapsulates the set of allowed connections.
	// Each allowed protocol is mapped to a list of the allowed port numbers.
	ProtocolsAndPorts map[v1.Protocol][]Port
}

// Port describes a port or a range of ports for allowed traffic
type Port struct {
	// Indicates the allowed port, if EndPort is not set.
	// Indicates the start port for a range of allowed ports, if EndPort is set.
	// Port has to be set.
	Port *int64
	// If set, indicates the end port for the range of ports starting from port.
	EndPort *int64
}

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
	res := []Peer2PeerConnection{}
	peerList := pe.GetPeersList() // pods and ip blocks
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
			connection := Peer2PeerConnection{
				Src:                  srcPeer.String(),
				Dst:                  dstPeer.String(),
				AllProtocolsAndPorts: allowedConnections.AllowAll,
				ProtocolsAndPorts:    map[v1.Protocol][]Port{},
			}
			protocolsMap := allowedConnections.GetProtocolsAndPortsMap()
			// convert each port range (list) to connlist.Port
			for protocol, ports := range protocolsMap {
				connection.ProtocolsAndPorts[protocol] = make([]Port, 0, len(ports))
				for i := range ports {
					startPort, endPort := ports[i][0], ports[i][1]
					port := Port{Port: &startPort}
					if endPort > startPort {
						port.EndPort = &endPort
					}
					connection.ProtocolsAndPorts[protocol][i] = port
				}
			}
			res = append(res, connection)
		}
	}
	return res, nil
}

// return a string representation for a Peer2PeerConnection object
func (pc *Peer2PeerConnection) String() string {
	var connStr string
	if pc.AllProtocolsAndPorts {
		connStr = "All Connections"
	} else if len(pc.ProtocolsAndPorts) == 0 {
		connStr = "No Connections"
	} else {
		connStrings := make([]string, 0, len(pc.ProtocolsAndPorts))
		index := 0
		for protocol, ports := range pc.ProtocolsAndPorts {
			connStrings[index] = string(protocol) + " " + portsString(ports)
			index++
		}
		sort.Strings(connStrings)
		connStr = strings.Join(connStrings, separator)
	}
	return fmt.Sprintf("%v => %v : %v", pc.Src, pc.Dst, connStr)
}

// get string of connections from list of Peer2PeerConnection objects
func ConnectionsListToString(conns []Peer2PeerConnection) string {
	connLines := make([]string, 0, len(conns))
	for i := range conns {
		connLines[i] = conns[i].String()
	}
	sort.Strings(connLines)
	return strings.Join(connLines, "\n")
}

// return a string representation for a Port object
func (p *Port) String() string {
	if p.EndPort != nil {
		return fmt.Sprintf("%v-%v", *p.Port, *p.EndPort)
	}
	return fmt.Sprintf("%v", *p.Port)
}

// get string representation for a list of port values
func portsString(ports []Port) string {
	portsStr := make([]string, 0, len(ports))
	for i := range ports {
		portsStr[i] = ports[i].String()
	}
	return strings.Join(portsStr, separator)
}
