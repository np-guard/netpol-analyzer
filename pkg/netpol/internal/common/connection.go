/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	v1 "k8s.io/api/core/v1"
)

// Connection represents a set of allowed connections between two peers
type Connection interface {
	// ProtocolsAndPortsMap returns the set of allowed connections
	ProtocolsAndPortsMap() map[v1.Protocol][]PortRange
	// AllConnections returns true if all ports are allowed for all protocols
	AllConnections() bool
	// IsEmpty returns true if no connection is allowed
	IsEmpty() bool
}

// PortRange describes a port or a range of ports for allowed traffic
// If start port equals end port, it represents a single port
// If NamedPort is known but input resources does not give hint for its matching port number, then port-name represents the PortRange
type PortRange interface {
	// Start is the start port
	Start() int64
	// End is the end port
	End() int64
	// NamedPort is the name of the port
	// NamedPort is used when the Start() and End() of the port are unknown
	NamedPort() string
	// String returns a string representation of the PortRange object
	String() string
}
