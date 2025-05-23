/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package cli

import (
	"errors"

	"github.com/np-guard/netpol-analyzer/pkg/internal/common"
	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
)

const typeStr = "string"

// focusDirection is a custom flag type.
// Cobra allows to define custom value types to be used as flags through the pflag.(*FlagSet).Var() method.
// defining a new type that implements the pflag.Value interface.
type focusDirection string

// String is used both by fmt.Print and by Cobra in help text
func (e *focusDirection) String() string {
	return string(*e)
}

// Set must have pointer receiver so it doesn't change the value of a copy
func (e *focusDirection) Set(v string) error {
	switch v {
	case common.IngressFocusDirection, common.EgressFocusDirection:
		*e = focusDirection(v)
		return nil
	default:
		return errors.New(netpolerrors.FocusDirectionOptions)
	}
}

// Type is only used in help text
func (e *focusDirection) Type() string {
	return typeStr
}

// Reset resets the value to empty string
func (e *focusDirection) Reset() {
	*e = ""
}

// explainOnly is a custom flag type.
// Cobra allows to define custom value types to be used as flags through the pflag.(*FlagSet).Var() method.
// defining a new type that implements the pflag.Value interface.
type explainOnly string

// String is used both by fmt.Print and by Cobra in help text
func (e *explainOnly) String() string {
	return string(*e)
}

// Set must have pointer receiver so it doesn't change the value of a copy
func (e *explainOnly) Set(v string) error {
	switch v {
	case common.ExplainOnlyAllow, common.ExplainOnlyDeny:
		*e = explainOnly(v)
		return nil
	default:
		return errors.New(netpolerrors.ExplainOnlyOptions)
	}
}

// Type is only used in help text
func (e *explainOnly) Type() string {
	return typeStr
}

// Reset resets the value to empty string
func (e *explainOnly) Reset() {
	*e = ""
}
