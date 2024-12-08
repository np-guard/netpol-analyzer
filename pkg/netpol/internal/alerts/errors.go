/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package alerts

import (
	"fmt"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// @TODO : to be updated with more errors (moving error strings from pkg\internal\netpolerrors\netpol_errors.go to here) #446

const (
	EndPortWithNamedPortErrStr = "endPort field cannot be defined if the port field is defined as a named (string) port"
)

// IllegalPortRangeError return a string describing the error when having an empty port range in a policy rule
func IllegalPortRangeError(start, end int64) string {
	return fmt.Sprintf("port range %d-%d is legal; start and end values of the port range should be in "+
		"{%d-%d} and end may not be less than start", start, end, common.MinPort, common.MaxPort)
}
