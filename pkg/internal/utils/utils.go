/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package utils

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	policyapi "sigs.k8s.io/network-policy-api/pkg/client/clientset/versioned"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
)

// this internal file contains code which is consumed by the netpol-analyzer commands in cli and netpol packages
const CtxTimeoutSeconds = 3

// UpdatePolicyEngineWithK8sPolicyAPIObjects inserts to the policy-engine all (baseline)admin network policies
func UpdatePolicyEngineWithK8sPolicyAPIObjects(pe *eval.PolicyEngine, clientset *policyapi.Clientset) error {
	ctx, cancel := context.WithTimeout(context.Background(), CtxTimeoutSeconds*time.Second)
	defer cancel()
	// get all admin-network-policies
	anpList, apiErr := clientset.PolicyV1alpha1().AdminNetworkPolicies().List(ctx, metav1.ListOptions{})
	if apiErr != nil {
		return apiErr
	}
	for i := range anpList.Items {
		if err := pe.InsertObject(&anpList.Items[i]); err != nil {
			return err
		}
	}
	// sort the admin-netpols by the priority - since their priority ordering is critic for computing allowed conns
	err := pe.SortAdminNetpolsByPriority()
	if err != nil {
		return err
	}
	// get baseline-admin-netpol
	banpList, apiErr := clientset.PolicyV1alpha1().BaselineAdminNetworkPolicies().List(ctx, metav1.ListOptions{})
	if apiErr != nil {
		return apiErr
	}
	for i := range banpList.Items {
		if err := pe.InsertObject(&banpList.Items[i]); err != nil {
			return err
		}
	}
	return nil
}
