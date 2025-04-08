/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package alerts

import (
	"fmt"

	"k8s.io/apimachinery/pkg/types"

	"github.com/np-guard/netpol-analyzer/pkg/internal/output"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

const (
	WarnPrefixPortName        = "port name: "
	WarnNamedPortIgnoredForIP = "named port is not defined for IP addresses; skipped"
	// example raising this warning: tests/anp_test_named_ports_multiple_peers

	K8sClusterDoesNotSupportNetworkPolicyAPI = "cluster does not support admin network policies"
	FocusDirectionFlag                       = "focus-direction"
	FocusWorkloadPeerFlag                    = "focusworkload-peer"
	WarnIgnoredWithoutExplain                = "explain-only may be used only with explain flag, will be ignored"
	WarnIgnoredWithoutFocusWorkload          = " may be used only with focusworkload flag, will be ignored"
	WarnUnsupportedIPv6Address               = "IPv6 addresses are not supported" // example raising this warning:
	// tests/anp_and_banp_using_networks_with_ipv6_test
	WarnUnsupportedNodesField = "Nodes field of an AdminNetworkPolicyEgressPeer is not supported" // example raising this
	// warning: tests/anp_and_banp_using_networks_and_nodes_test
	// connlist warnings
	EmptyConnListErrStr    = "Connectivity map report will be empty."
	NoIngressSourcesErrStr = "The ingress-controller workload was not added to the analysis, since Ingress/Route resources were not found."
	NoAllowedConnsWarning  = "Connectivity analysis found no allowed connectivity between pairs from the configured workloads or" +
		" external IP-blocks"
	WarnIgnoredExposureOnLiveCluster = "exposure analysis is not supported on live-cluster; exposure flag will be ignored"
	warnIgnoredUDN                   = udnPrefix + "%s is ignored."
)

func WarnIgnoredExposure(flag1, flag2 string) string {
	return "exposure analysis is not relevant when both " + flag1 + " and " + flag2 +
		" are used; exposure flag will be ignored"
}

// BlockedIngressWarning returns warning string of a blocked ingress on peer
func BlockedIngressWarning(objKind, objName, peerStr string) string {
	return objKind + " resource " + objName + " specified workload " + peerStr + " as a backend, but network policies are blocking " +
		"ingress connections from an arbitrary in-cluster source to this workload. " +
		"Connectivity map will not include a possibly allowed connection between the ingress controller and this workload."
}

func WarnIncompatibleFormat(format string) string {
	return fmt.Sprintf("explain flag is supported only with %s output format;"+
		" ignoring this flag for the required output format %s", output.DefaultFormat, format)
}

func WarnUnmatchedNamedPort(namedPort, peerStr string) string {
	return fmt.Sprintf("%s %q has no match in the configuration of the destination peer %q",
		WarnPrefixPortName, namedPort, peerStr)
	// examples this warning is raised:
	// - tests/netpol_named_port_test
	// - tests/anp_banp_test_with_named_port_unmatched
}

func WarnMissingNamespaceOfUDN(udnName, udnNs string) string {
	return fmt.Sprintf(warnIgnoredUDN+" Namespace %s does not exist in the input resources",
		types.NamespacedName{Name: udnName, Namespace: udnNs}.String(), udnNs)
}

func WarnNamespaceDoesNotSupportUDN(udnName, udnNs string) string {
	return fmt.Sprintf(warnIgnoredUDN+" Namespace %s does not contain %s label",
		types.NamespacedName{Name: udnName, Namespace: udnNs}.String(), udnNs, common.PrimaryUDNLabel)
}

func NotSupportedUDNRole(udn string) string {
	return fmt.Sprintf(warnIgnoredUDN+" Secondary user-defined-network is not supported", udn)
}
