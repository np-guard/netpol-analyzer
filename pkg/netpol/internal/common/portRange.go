package common

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
