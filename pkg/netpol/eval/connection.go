package eval

import (
	v1 "k8s.io/api/core/v1"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval/internal/k8s"
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
type PortRange interface {
	// Start is the start port
	Start() int64
	// End is the end port
	End() int64
	// String returns a string representation of the PortRange object
	String() string
}

// k8sConnectionSetWrapper implements the Connection interface
type k8sConnectionSetWrapper struct {
	protocolsAndPortsMap map[v1.Protocol][]PortRange
	connectionSet        k8s.ConnectionSet
}

func (c *k8sConnectionSetWrapper) ProtocolsAndPortsMap() map[v1.Protocol][]PortRange {
	return c.protocolsAndPortsMap
}

func (c *k8sConnectionSetWrapper) AllConnections() bool {
	return c.connectionSet.AllowAll
}
func (c *k8sConnectionSetWrapper) IsEmpty() bool {
	return c.connectionSet.IsEmpty()
}

func (c *k8sConnectionSetWrapper) ConnectionSet() k8s.ConnectionSet {
	return c.connectionSet
}

// convert an input k8s.ConnectionSet object to a connectionObj that implements Connection interface
func getConnectionObject(conn k8s.ConnectionSet) Connection {
	protocolsMap := conn.ProtocolsAndPortsMap()
	res := &k8sConnectionSetWrapper{
		protocolsAndPortsMap: make(map[v1.Protocol][]PortRange, len(protocolsMap)),
		connectionSet:        conn,
	}
	for protocol, ports := range protocolsMap {
		res.protocolsAndPortsMap[protocol] = make([]PortRange, len(ports))
		for i, portRange := range ports {
			res.protocolsAndPortsMap[protocol][i] = portRange
		}
	}
	return res
}
