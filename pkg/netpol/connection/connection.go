package connection

import (
	v1 "k8s.io/api/core/v1"
)

// AllowedSet represents a set of allowed connections between two peers
type AllowedSet interface {
	// ProtocolsAndPortsMap returns the set of allowed connections
	ProtocolsAndPortsMap() map[v1.Protocol][]PortRange
	// IsAllConnections returns true if all ports are allowed for all protocols
	IsAllConnections() bool
	// IsEmpty returns true if no connection is allowed
	IsEmpty() bool
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
