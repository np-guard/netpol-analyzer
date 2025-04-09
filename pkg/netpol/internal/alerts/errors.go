/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package alerts

import (
	"fmt"

	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

const (
	// errors from k8s objects (eval/internal/k8s pkg)
	CidrErrTitle               = "CIDR error"
	SelectorErrTitle           = "selector error"
	RulePeerErrTitle           = "rule NetworkPolicyPeer error"
	EmptyRulePeerErrStr        = "cannot have empty rule peer"
	CombinedRulePeerErrStr     = "cannot have both IPBlock and PodSelector/NamespaceSelector set"
	NamedPortErrTitle          = "named port error"
	ConvertNamedPortErrStr     = "cannot convert named port for an IP destination"
	EndPortWithNamedPortErrStr = "endPort field cannot be defined if the port field is defined as a named (string) port"
	InvalidCIDRAddr            = "invalid CIDR address"
	oneFieldSetErr             = "exactly one field must be set"
	OneFieldSetRulePeerErr     = oneFieldSetErr + " in a rule peer"
	OneFieldSetSubjectErr      = oneFieldSetErr + " in a subject"
	UnknownRuleActionErr       = "unrecognized action"
	ANPPortsError              = "exactly one field must be set in an AdminNetworkPolicyPort"
	ANPIngressRulePeersErr     = "from field must be defined and contain at least one item"
	ANPEgressRulePeersErr      = "to field must be defined and contain at least one item"

	// errors from malformed yamls which are raised by external libraries (used in connlist_test/ diff_test)
	InvalidKeyVal           = "key: Invalid value"
	UnrecognizedValType     = "unrecognized type"
	SliceFromMapErr         = "cannot restore slice from map"
	PathNotExistErr         = "does not exist"
	UnknownFileExtensionErr = "recognized file extensions are"
	MissingObjectErr        = "is missing in"
	UnmarshalErr            = "cannot unmarshal array into Go value of type unstructured.detector"
	UnableToDecodeErr       = "unable to decode"

	// connlist pkg errors
	ConversionToConnectionSetErr = "failed conversion from AllowedSet to ConnectionSet"

	// eval pkg errors
	NotFoundNamespace                = "could not find peer namespace"
	BANPAlreadyExists                = "only one baseline admin network policy may be provided in input resources; one already exists"
	BANPNameAssertion                = "only one baseline admin network policy with metadata.name=default can be created in the cluster"
	NilRepresentativePodSelectorsErr = "representative pod might not be generated if it does not have any representative selector"
)

// errors from k8s objects:

// IllegalPortRangeError return a string describing the error when having an empty port range in a policy rule
func IllegalPortRangeError(start, end int64) string {
	return fmt.Sprintf("port range %d-%d is legal; start and end values of the port range should be in "+
		"{%d-%d} and end may not be less than start", start, end, common.MinPort, common.MaxPort)
}

// eval pkg errors:

// NotSupportedPodResourcesErrorStr returns error string of not supported pods with same ownerRef but different labels
// which are selected by a policy
func NotSupportedPodResourcesErrorStr(ownerRefName string) string {
	return "Found Pods of the same owner workload `" + ownerRefName +
		"` and with differences in their labels, while a network policy contains selectors impacted by this gap.\n"
}

// InvalidPeerErrStr returns error string of an invalid peer
func InvalidPeerErrStr(peer string) string {
	return peer + " is not a valid peer"
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

const PriorityErrExplain = "Two policies are considered to be conflicting if they are assigned the same priority."

// SamePriorityErr returns the error message if a priority appears more than once in different admin-network-policies
func SamePriorityErr(name1, name2 string) string {
	return "Admin Network Policies: " + name1 + " and " + name2 + " have same priority;" + PriorityErrExplain
}

// PriorityValueErr returns error message of invalid priority value in an admin-network-policy
func PriorityValueErr(name string, priority int32) string {
	return fmt.Sprintf("Invalid Priority Value: %d in Admin Network Policy: %q; Priority value must be between %d-%d", priority, name,
		common.MinANPPriority, common.MaxANPPriority)
}

const uniquenessRequest = "Only one object of a given kind can have a given name at a time."

// ANPsWithSameNameErr returns error message when there are two admin-network-policies with same name in the manifests
func ANPsWithSameNameErr(anpName string) string {
	return fmt.Sprintf("an AdminNetworkPolicy with name %q is already found. %s", anpName, uniquenessRequest)
}

func NPWithSameNameError(npName string) string {
	return fmt.Sprintf("NetworkPolicy %q already exists. %s", npName, uniquenessRequest)
}

func NSWithSameNameError(ns string) string {
	return fmt.Sprintf("Namespace %q already exists. %s", ns, uniquenessRequest)
}

// connlist pkg errors:

// WorkloadDoesNotExistErrStr returns error string of missing workload for connlist with focus-workload
func WorkloadDoesNotExistErrStr(workload string) string {
	return "Workload " + workload + " does not exist in the input resources."
}

const semiColon = "; "

func FocusDirectionNotSupported(focusDirection string) string {
	return "invalid focus direction value: " + focusDirection + semiColon + netpolerrors.FocusDirectionOptions
}

func ExplainOnlyNotSupported(explainOnly string) string {
	return "invalid explain only value: " + explainOnly + semiColon + netpolerrors.ExplainOnlyOptions
}

func InvalidFocusConnPortNumber(focusConn, port string) string {
	return netpolerrors.InvalidFocusConn + focusConn + "; invalid port number: " + port
}

func InvalidFocusConnFormat(focusConn string) string {
	return netpolerrors.InvalidFocusConn + focusConn + "; must be <protocol-port> format"
}

func InvalidFocusConnProtocol(focusConn, protocol string) string {
	return netpolerrors.InvalidFocusConn + focusConn + "; unknown protocol: " + protocol
}

func OnePrimaryUDNAssertion(ns string) string {
	return "only one primary UserDefinedNetwork may be assigned to a single namespace. More than one UDN is assigned to namespace: " + ns
}

const udnPrefix = "user-defined-network: "

func ErrUDNInDefaultNs(udnName, namespace string) string {
	return udnPrefix + udnName + " is assigned to namespace: " + namespace +
		"; UserDefinedNetwork CRs should not be created in this namespace." +
		" This can result in no isolation and, as a result, could introduce security risks to the cluster."
}

func UDNNameAssertion(udn string) string {
	return "illegal name of user-defined-network: " + udn + "; Name of UserDefinedNetwork resource should not be default"
}

func InvalidKeyValue(udn, key, val string) string {
	return udnPrefix + udn + "; Invalid value: " + val + " for key: " + key
}

func DisMatchLayerConfiguration(udn, topology string) string {
	return udnPrefix + udn + "; Mismatch between topology value: " + topology + " and actual layer configuration"
}
