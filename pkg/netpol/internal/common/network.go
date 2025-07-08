/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import "github.com/np-guard/netpol-analyzer/pkg/manifests/parser"

type NetworkInterface int

const (
	PodNetwork NetworkInterface = iota
	Primary
	Secondary
)

type NetworkResource int

const (
	Default NetworkResource = iota
	UDN
	CUDN
	NAD
)

func ResourceString(r NetworkResource) string {
	switch r {
	case UDN:
		return parser.UserDefinedNetwork
	case CUDN:
		return parser.ClusterUserDefinedNetwork
	case NAD:
		return parser.NetworkAttachmentDefinition
	default:
		return "None"
	}
}

const (
	podNetworkName = "pod_network"
)

// NetworkData contains data of :
// in policy-engine: the network from the inserted object (UserDefinedNetwork/ClusterUserDefinedNetwork/NetworkAttachmentDefinition)
// in connection-set: the network that enables connection between two peers
type NetworkData struct {
	NetworkName  string
	Interface    NetworkInterface // PodNetwork/Primary/Secondary
	ResourceKind NetworkResource  // UDN/CUDN/NAD
	ResourceName string
}

// creates an object for default pod-network connection
func DefaultNetworkData() NetworkData {
	return NetworkData{
		NetworkName:  podNetworkName,
		Interface:    PodNetwork,
		ResourceKind: Default,
	}
}

// IsEmpty returns if no network data available for a connection
func (nd *NetworkData) IsEmpty() bool {
	return nd.NetworkName == ""
}

// SecondaryNetworkData used in policy-engine to store data of secondary network
type SecondaryNetworkData struct {
	NetworkData NetworkData
	Namespaces  map[string]bool
	// Config string// @todo: will be added to compare the configurations of Secondary networks with same name - must be equal
	// "Networks names must be unique. For example, creating multiple NetworkAttachmentDefinition CRDs with different configurations that
	// reference the same network is unsupported."
}
