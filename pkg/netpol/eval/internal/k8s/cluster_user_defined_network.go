/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package k8s

import (
	udnv1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/userdefinednetwork/v1"
)

type ClusterUserDefinedNetwork udnv1.ClusterUserDefinedNetwork // aliasing ovn-k8s Cluster-UDN object

func (cudn *ClusterUserDefinedNetwork) IsCUDNPrimary() bool {
	return (cudn.Spec.Network.Layer2 != nil && cudn.Spec.Network.Layer2.Role == udnv1.NetworkRolePrimary) ||
		(cudn.Spec.Network.Layer3 != nil && cudn.Spec.Network.Layer3.Role == udnv1.NetworkRolePrimary)
}

// CheckFieldsValidity returns whether values of specific required fields are valid according to
// https://docs.redhat.com/en/documentation/openshift_container_platform/4.18/html/networking/
// multiple-networks#nw-cudn-cr_about-user-defined-networks
func (cudn *ClusterUserDefinedNetwork) CheckFieldsValidity() (err error) {
	if err := checkTopologyValidity(cudn.Name, cudn.Spec.Network.Topology, cudn.Spec.Network.Layer2, cudn.Spec.Network.Layer3); err != nil {
		return err
	}
	return checkRoleValidity(cudn.Name, cudn.Spec.Network.Layer2, cudn.Spec.Network.Layer3)
}
