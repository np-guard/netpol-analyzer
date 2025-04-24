/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package netpolerrors

import (
	"github.com/np-guard/netpol-analyzer/pkg/internal/common"
)

const (
	// cli general errors
	VerbosityFlagsMisUseErrStr = "-q and -v cannot be specified together"
	UnknownCommandErr          = "unknown command"

	// parser errors (manifests pkg)
	NoK8sWorkloadResourcesFoundErrorStr      = "no relevant Kubernetes workload resources found"
	NoK8sNetworkPolicyResourcesFoundErrorStr = "no relevant Kubernetes network policy resources found"
	MalformedYamlDocErrorStr                 = "YAML document is malformed"
	FailedReadingFileErrorStr                = "error reading file"
	NoDocumentIDErrorStr                     = "no document ID is available for this error"
	ConversionToUnstructuredErr              = "failed conversion from resource.Info to unstructured.Unstructured"

	// connlist errors used in cli pkg too
	ErrGettingResInfoFromDir = "Error getting resourceInfos from dir path"

	// list command flags errors
	FocusDirectionOptions = "must be one of " + common.IngressFocusDirection + "," + common.EgressFocusDirection
	ExplainOnlyOptions    = "must be one of " + common.ExplainOnlyAllow + "," + common.ExplainOnlyDeny
	InvalidFocusConn      = "invalid focus connection value: "
	InvalidFocusConnSet   = "invalid focus connection set - may contain only one protocol-port"

	// evaluate command-line errors
	NoSourceDefinedErr     = "no source defined, source pod and namespace or external IP required"
	OnlyOneSrcFlagErrStr   = "only one of source pod and namespace or external IP can be defined, not both"
	NoDestDefinedErr       = "no destination defined, destination pod and namespace or external IP required"
	OnlyOneDstFlagErrStr   = "only one of destination pod and namespace or external IP can be defined, not both"
	OnlyOneIPPeerErrStr    = "only one of source or destination can be defined as external IP, not both"
	RequiredDstPortFlagErr = "destination port name or value is required"

	// diff command-line errors
	RequiredFlagsErr = "both directory paths dir1 and dir2 are required"
	FlagMisUseErr    = "dirpath flag is not used with diff command"

	// severe errors constants from `orig errors` which are raised by external libraries (used in cli/command_test/ netpol/connlist_test)
	WrongStartCharacterErr = "found character that cannot start any token"

	// output related errors
	GraphvizIsNotFound = "svg graphs can not be created since dot executable of graphviz was not found"
)

// FormatNotSupportedErrStr returns error string of a not supported format for connlist or diff results
func FormatNotSupportedErrStr(format string) string {
	return format + " output format is not supported."
}

// NotFoundPeerErrStr returns error string of a peer could not be found
func NotFoundPeerErrStr(peer string) string {
	return "could not find peer " + peer
}

const colonSep = ": "

// ConcatErrors returns the given errors' messages concatenated by colon
func ConcatErrors(err1, err2 string) string {
	return err1 + colonSep + err2
}
