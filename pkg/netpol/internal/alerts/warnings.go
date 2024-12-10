/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package alerts

import "fmt"

func WarnUnmatchedNamedPort(namedPort, peerStr string) string {
	return fmt.Sprintf("%s %q has no match in the configuration of the destination peer %q",
		WarnPrefixPortName, namedPort, peerStr)
	// examples this warning is raised:
	// - tests/netpol_named_port_test
	// - tests/anp_banp_test_with_named_port_unmatched
}

const (
	WarnPrefixPortName        = "port name: "
	WarnNamedPortIgnoredForIP = "named port is not defined for IP addresses; skipped"
	// example raising this warning: tests/anp_test_named_ports_multiple_peers
)

var (
	WarnUnsupportedIPv6Address = "IPv6 addresses are not supported" // example raising this warning:
	// tests/anp_and_banp_using_networks_with_ipv6_test
	WarnUnsupportedNodesField = "Nodes field of an AdminNetworkPolicyEgressPeer is not supported" // example raising this
	// warning: tests/anp_and_banp_using_networks_and_nodes_test
)
