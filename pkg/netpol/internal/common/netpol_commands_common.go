package common

import (
	v1 "k8s.io/api/core/v1"
)

// NetpolError holds information about a single error/warning that occurred during running
// connectivity analysis command (list or diff)
type NetpolError interface {
	IsFatal() bool
	IsSevere() bool
	Error() error
	Location() string
}

type AllowedConnectivity interface {
	// AllProtocolsAndPorts returns true if all ports are allowed for all protocols
	AllProtocolsAndPorts() bool
	// ProtocolsAndPorts returns the set of allowed connections
	ProtocolsAndPorts() map[v1.Protocol][]PortRange
}

// AllowedConns implements the AllowedConnectivity interface
type AllowedConns struct {
	AllConnections       bool
	ProtocolsAndPortsMap map[v1.Protocol][]PortRange
}

func (a *AllowedConns) AllProtocolsAndPorts() bool {
	return a.AllConnections
}

func (a *AllowedConns) ProtocolsAndPorts() map[v1.Protocol][]PortRange {
	return a.ProtocolsAndPortsMap
}

// Ingress Controller const - the name and namespace of an ingress-controller pod
const (
	//  The actual ingress controller pod is usually unknown and not available in the input resources for the analysis.
	// IngressPodName and IngressPodNamespace are used to represent that pod with those placeholder values for name and namespace.
	IngressPodName      = "ingress-controller"
	IngressPodNamespace = "ingress-controller-ns"
)
