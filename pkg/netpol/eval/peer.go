package eval

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
}
