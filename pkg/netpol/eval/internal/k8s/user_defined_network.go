/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package k8s

import (
	"errors"

	udnv1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/userdefinednetwork/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/alerts"
)

type UserDefinedNetwork udnv1.UserDefinedNetwork // aliasing ovn-k8s UDN object

// IsUDNPrimary returns true if the role of the UDN is Primary
func (udn *UserDefinedNetwork) IsUDNPrimary() bool {
	return (udn.Spec.Layer2 != nil && udn.Spec.Layer2.Role == udnv1.NetworkRolePrimary) ||
		(udn.Spec.Layer3 != nil && udn.Spec.Layer3.Role == udnv1.NetworkRolePrimary)
}

const (
	topologyStr = "topology"
	roleStr     = "role"
)

// CheckFieldsValidity returns whether values of specific required fields are valid according to
// https://pkg.go.dev/github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/userdefinednetwork/v1#UserDefinedNetworkSpec
func (udn *UserDefinedNetwork) CheckFieldsValidity() (err error) {
	udnName := types.NamespacedName{Namespace: udn.Namespace, Name: udn.Name}.String()
	if err := checkTopologyValidity(udnName, udn.Spec.Topology, udn.Spec.Layer2, udn.Spec.Layer3); err != nil {
		return err
	}

	return checkRoleValidity(udnName, udn.Spec.Layer2, udn.Spec.Layer3)
}

func checkTopologyValidity(udnName string, topology udnv1.NetworkTopology, layer2 *udnv1.Layer2Config, layer3 *udnv1.Layer3Config) error {
	// Spec.Topology : Allowed values are "Layer3", "Layer2"
	if topology != udnv1.NetworkTopologyLayer2 && topology != udnv1.NetworkTopologyLayer3 {
		return errors.New(alerts.InvalidKeyValue(udnName, topologyStr, string(topology)))
	}
	// if Topology is Layer2 then Layer3 field should be nil and vice-versa
	if (topology == udnv1.NetworkTopologyLayer2 && layer3 != nil) ||
		(topology == udnv1.NetworkTopologyLayer3 && layer2 != nil) {
		return errors.New(alerts.DisMatchLayerConfiguration(udnName, string(topology)))
	}
	return nil
}

func checkRoleValidity(udnName string, layer2 *udnv1.Layer2Config, layer3 *udnv1.Layer3Config) error {
	// the Role field : Allowed values are "Primary" and "Secondary".
	if layer2 != nil && layer2.Role != udnv1.NetworkRolePrimary && layer2.Role != udnv1.NetworkRoleSecondary {
		return errors.New(alerts.InvalidKeyValue(udnName, roleStr, string(layer2.Role)))
	}
	if layer3 != nil && layer3.Role != udnv1.NetworkRolePrimary && layer3.Role != udnv1.NetworkRoleSecondary {
		return errors.New(alerts.InvalidKeyValue(udnName, roleStr, string(layer3.Role)))
	}
	return nil
}
