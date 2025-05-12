/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package k8s

import (
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
	topology = "topology"
	role     = "role"
)

// CheckFieldsValidity returns whether values of specific required fields are valid according to
// https://pkg.go.dev/github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/userdefinednetwork/v1#UserDefinedNetworkSpec
func (udn *UserDefinedNetwork) CheckFieldsValidity() (valid bool, errMsg string) {
	udnName := types.NamespacedName{Namespace: udn.Namespace, Name: udn.Name}.String()
	// Spec.Topology : Allowed values are "Layer3", "Layer2"
	if udn.Spec.Topology != udnv1.NetworkTopologyLayer2 && udn.Spec.Topology != udnv1.NetworkTopologyLayer3 {
		return false, alerts.InvalidKeyValue(udnName, topology, string(udn.Spec.Topology))
	}
	// if Topology is Layer2 then Layer3 field should be nil and vice-versa
	if (udn.Spec.Topology == udnv1.NetworkTopologyLayer2 && udn.Spec.Layer3 != nil) ||
		(udn.Spec.Topology == udnv1.NetworkTopologyLayer3 && udn.Spec.Layer2 != nil) {
		return false, alerts.DisMatchLayerConfiguration(udnName, string(udn.Spec.Topology))
	}
	// the Role field : Allowed values are "Primary" and "Secondary".
	if udn.Spec.Layer2 != nil && udn.Spec.Layer2.Role != udnv1.NetworkRolePrimary && udn.Spec.Layer2.Role != udnv1.NetworkRoleSecondary {
		return false, alerts.InvalidKeyValue(udnName, role, string(udn.Spec.Layer2.Role))
	}
	if udn.Spec.Layer3 != nil && udn.Spec.Layer3.Role != udnv1.NetworkRolePrimary && udn.Spec.Layer3.Role != udnv1.NetworkRoleSecondary {
		return false, alerts.InvalidKeyValue(udnName, role, string(udn.Spec.Layer3.Role))
	}
	return true, ""
}
