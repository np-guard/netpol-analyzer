package diff

import (
	v1 "k8s.io/api/core/v1"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/common"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
)

// ConnectivityDiff captures the set of differences in terms of connectivity between two input k8s resource sets
type ConnectivityDiff interface {
	// RemovedConnections is a list of differences where the specified conn only exists in ref1
	RemovedConnections() []SrcDstDiff

	// AddedConnections  is a list of differences where the specified conn only exists in ref2
	AddedConnections() []SrcDstDiff

	// ChangedConnections is a list of differences where the specified conn exists in ref1 and ref2 but not identical
	// connection properties
	ChangedConnections() []SrcDstDiff

	// UnchangedConnections is a list of connections that exists in ref1 and ref2, and are identical
	UnchangedConnections() []SrcDstDiff

	// IsEmpty returns true if there is no diff in connectivity, i.e. removed, added and changed connections are empty
	IsEmpty() bool
}

// SrcDstDiff captures connectivity diff per one src-dst pair
type SrcDstDiff interface {
	// Src returns the source peer
	Src() Peer
	// Dst returns the destination peer
	Dst() Peer
	// Ref1Connectivity returns the AllowedConnectivity from src to dst in ref1
	Ref1Connectivity() AllowedConnectivity
	// Ref2Connectivity returns the AllowedConnectivity from src to dst in ref2
	Ref2Connectivity() AllowedConnectivity
	// IsSrcNewOrRemoved returns true if the src peer exists only in ref2 (if DiffType is Added) or if
	// the src peer exists only in ref1 (if DiffType is Removed)
	IsSrcNewOrRemoved() bool
	// IsDstNewOrRemoved returns true if the dst peer exists only in ref2 (if DiffType is Added) or if
	// the dst peer exists only in ref1 (if DiffType is Removed)
	IsDstNewOrRemoved() bool
	// DiffType returns the diff type of ref2 w.r.t ref1, which can be ChangedType/RemovedType/AddedType/NonChangedType
	DiffType() DiffTypeStr
}

type Peer eval.Peer

type AllowedConnectivity interface {
	// AllProtocolsAndPorts returns true if all ports are allowed for all protocols
	AllProtocolsAndPorts() bool
	// ProtocolsAndPorts returns the set of allowed connections
	ProtocolsAndPorts() map[v1.Protocol][]common.PortRange
}

type DiffTypeStr string

const (
	// diff types
	ChangedType   DiffTypeStr = "changed"
	RemovedType   DiffTypeStr = "removed"
	AddedType     DiffTypeStr = "added"
	UnchangedType DiffTypeStr = "unchanged"
)
