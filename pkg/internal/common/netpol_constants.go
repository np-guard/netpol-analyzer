/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

const (
	// according to this: https://network-policy-api.sigs.k8s.io/api-overview/#adminnetworkpolicy-priorities
	// The Priority field in the ANP spec is defined as an integer value within the range 0 to 1000
	MinANPPriority = 0
	MaxANPPriority = 1000

	CtxTimeoutSeconds = 3
)

// Focus direction values consts
const (
	BothFocusDirection    = "both"
	IngressFocusDirection = "ingress"
	EgressFocusDirection  = "egress"
	DefaultFocusDirection = BothFocusDirection
)
