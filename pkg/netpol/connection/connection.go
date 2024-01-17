package connection

import (
	v1 "k8s.io/api/core/v1"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// Connection represents a set of allowed connections between two peers
type Connection interface {
	// ProtocolsAndPortsMap returns the set of allowed connections
	ProtocolsAndPortsMap() map[v1.Protocol][]common.PortRange
	// AllConnections returns true if all ports are allowed for all protocols
	AllConnections() bool
	// IsEmpty returns true if no connection is allowed
	IsEmpty() bool
}
