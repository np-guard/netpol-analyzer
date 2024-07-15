/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package netpolerrors

import "fmt"

const (
	VerbosityFlagsMisUseErrStr = "-q and -v cannot be specified together"
	// k8s errors
	CidrErrTitle           = "CIDR error"
	SelectorErrTitle       = "selector error"
	RulePeerErrTitle       = "rule NetworkPolicyPeer error"
	EmptyRulePeerErrStr    = "cannot have empty rule peer"
	CombinedRulePeerErrStr = "cannot have both IPBlock and PodSelector/NamespaceSelector set"
	NamedPortErrTitle      = "named port error"
	ConvertNamedPortErrStr = "cannot convert named port for an IP destination"

	// parser errors
	NoK8sWorkloadResourcesFoundErrorStr      = "no relevant Kubernetes workload resources found"
	NoK8sNetworkPolicyResourcesFoundErrorStr = "no relevant Kubernetes network policy resources found"
	MalformedYamlDocErrorStr                 = "YAML document is malformed"
	FailedReadingFileErrorStr                = "error reading file"
	NoDocumentIDErrorStr                     = "no document ID is available for this error"
	ConversionToUnstructuredErr              = "failed conversion from resource.Info to unstructured.Unstructured"

	// connlist errors
	EmptyConnListErrStr    = " Connectivity map report will be empty."
	NoIngressSourcesErrStr = "The ingress-controller workload was not added to the analysis, since Ingress/Route resources were not found."
	NoAllowedConnsWarning  = "Connectivity analysis found no allowed connectivity between pairs from the configured workloads or" +
		" external IP-blocks"

	ErrGettingResInfoFromDir     = "Error getting resourceInfos from dir path"
	ConversionToConnectionSetErr = "failed conversion from AllowedSet to ConnectionSet"

	// eval errors
	NoSourceDefinedErr     = "no source defined, source pod and namespace or external IP required"
	NotFoundNamespace      = "could not find peer namespace"
	OnlyOneSrcFlagErrStr   = "only one of source pod and namespace or external IP can be defined, not both"
	NoDestDefinedErr       = "no destination defined, destination pod and namespace or external IP required"
	OnlyOneDstFalgErrStr   = "only one of destination pod and namespace or external IP can be defined, not both"
	OnlyOneIPPeerErrStr    = "only one of source or destination can be defined as external IP, not both"
	RequiredDstPortFlagErr = "destination port name or value is required"

	// diff command errors
	RequiredFlagsErr = "both directory paths dir1 and dir2 are required"
	FlagMisUseErr    = "dirpath flag is not used with diff command"

	// errors consts from `orig errors` that are raised by external libraries
	InvalidCIDRAddr         = "invalid CIDR address"
	InvalidKeyVal           = "key: Invalid value"
	UnrecognizedValType     = "unrecognized type"
	SliceFromMapErr         = "cannot restore slice from map"
	PathNotExistErr         = "does not exist"
	UnknownFileExtensionErr = "recognized file extensions are"
	MissingObjectErr        = "is missing in"
	WrongStartCharacterErr  = "found character that cannot start any token"
	UnmarshalErr            = "cannot unmarshal array into Go value of type unstructured.detector"
	UnableToDecodeErr       = "unable to decode"

	UnknownCommandErr = "unknown command"
)

// NotSupportedPodResourcesErrorStr returns error string of not supported pods with same ownerRef but different labels
func NotSupportedPodResourcesErrorStr(ownerRefName string) string {
	return "Input Pod resources are not supported for connectivity analysis. Found Pods of the same owner " +
		ownerRefName + " but with different set of labels."
}

// WorkloadDoesNotExistErrStr returns error string of missing workload for connlist with focusworkload
func WorkloadDoesNotExistErrStr(workload string) string {
	return "Workload " + workload + " does not exist in the input resources." + EmptyConnListErrStr
}

// FormatNotSupportedErrStr returns error string of a not supported format for connlist or diff results
func FormatNotSupportedErrStr(format string) string {
	return format + " output format is not supported."
}

// NotFoundPeerErrStr returns error string of a peer could not be found
func NotFoundPeerErrStr(peer string) string {
	return "could not find peer " + peer
}

// InvalidPeerErrStr returns error string of an invalid peer
func InvalidPeerErrStr(peer string) string {
	return peer + " is not a valid peer"
}

// BlockedIngressWarning returns warning string of a blocked ingress on peer
func BlockedIngressWarning(objKind, objName, peerStr string) string {
	return objKind + " resource " + objName + " specified workload " + peerStr + " as a backend, but network policies are blocking " +
		"ingress connections from an arbitrary in-cluster source to this workload. " +
		"Connectivity map will not include a possibly allowed connection between the ingress controller and this workload."
}

// MissingNamespaceErrStr returns error string of a missing namespace of a peer
func MissingNamespaceErrStr(nsName, peerName string) string {
	return "error: namespace " + nsName + " of pod " + peerName + " is missing"
}

// NotPeerErrStr returns error string of a peer that is not workload peer
func NotPeerErrStr(peerStr string) string {
	return "peer: " + peerStr + ", is not a WorkloadPeer"
}

func NotRepresentativePeerErrStr(peerStr string) string {
	return peerStr + ", is not a Representative peer"
}

// BothSrcAndDstIPsErrStr returns error string that conn from ip to ip is not supported
func BothSrcAndDstIPsErrStr(srcStr, dstStr string) string {
	return fmt.Sprintf("cannot have both srcPeer and dstPeer of IP types: src: %s, dst: %s", srcStr, dstStr)
}

const colonSep = ": "

// ConcatErrors returns the given errors' messages concatenated by colon
func ConcatErrors(err1, err2 string) string {
	return err1 + colonSep + err2
}
