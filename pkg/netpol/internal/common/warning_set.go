/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import "github.com/np-guard/netpol-analyzer/pkg/logger"

type Warnings map[string]bool // set of warnings which are raised by any policy object

// AddWarning adds the given warning to the current warnings set if not found
func (w Warnings) AddWarning(warning string) {
	if !w[warning] {
		w[warning] = true
	}
}

// LogPolicyWarnings logs current warnings into the given logger
func (w Warnings) LogPolicyWarnings(l logger.Logger) {
	for warning := range w {
		l.Warnf(warning)
	}
}
