package eval

import "github.com/np-guard/netpol-analyzer/pkg/netpol/eval/internal/k8s"

// Peer can either represent a Pod or an IP address
type Peer interface {
	// Name returns a peer's name in case the peer is a pod/workload, else it returns an empty string
	Name() string
	// Namespace returns a peer's namespace in case the peer is a pod/workload, else it returns an empty string
	Namespace() string
	// IP returns an IP address string in case peer is IP address, else it returns an empty string
	IP() string
	// IsPeerIPType returns true if  peer is IP address
	IsPeerIPType() bool
	// String returns a string representation of the Peer object
	String() string
	// Kind returns a string of the peer kind in case the peer is a pod/workload, else it returns an empty string
	Kind() string
	// GetAllowedConnectionsToPod returns ConnectionSet of the allowed connections to the Pod object of the peer
	// if it is a pod, else returns empty ConnectionSet
	GetAllowedConnectionsToPod() k8s.ConnectionSet
}
