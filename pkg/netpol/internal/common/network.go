/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

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

const (
	PodNetworkStr  = "PodNetwork"
	PrimaryStr     = "Primary"
	SecondaryStr   = "Secondary"
	UDNStr         = "UDN"
	CUDNStr        = "CUDN"
	NADStr         = "NAD"
	podNetworkName = "pod_network"
)

type NetworkData struct {
	NetworkName  string
	Interface    NetworkInterface
	Resource     NetworkResource
	ResourceName string
	// Config // will be added to compare the configurations of Secondary networks with same name - must be equal
}

func DefaultNetworkData() NetworkData {
	return NetworkData{
		NetworkName: podNetworkName,
		Interface:   PodNetwork,
		Resource:    Default,
	}
}

func PrimaryUDNNetwork(name string) NetworkData {
	return NetworkData{
		NetworkName: name,
		Interface:   Primary,
		Resource:    UDN,
	}
}

func PrimaryCUDNNetwork(name string) NetworkData {
	return NetworkData{
		NetworkName: name,
		Interface:   Primary,
		Resource:    CUDN,
	}
}

func (nd *NetworkData) IsEmpty() bool {
	return nd.NetworkName == ""
}
