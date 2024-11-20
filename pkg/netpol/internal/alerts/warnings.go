/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package alerts

import "fmt"

func WarnUnmatchedNamedPort(namedPort, peerStr string) string {
	return fmt.Sprintf("port name: %q has no match in the configuration of the destination peer %q; %s",
		namedPort, peerStr, ignoreMsg)
	// examples this warning is raised:
	// - tests/netpol_named_port_test
	// - tests/anp_banp_test_with_named_port_unmatched
}

const (
	ignoreMsg          = "it will be ignored, and will not appear in the connectivity results."
	WarnEmptyPortRange = "port range is empty, skipped." // example raising this warning: tests/anp_test_with_empty_port_range
)

var (
	WarnUnsupportedIPv6Address = "IPv6 addresses are not supported; " + ignoreMsg // example raising this warning:
	// tests/anp_and_banp_using_networks_with_ipv6_test
	WarnUnsupportedNodesField = "Nodes field of an AdminNetworkPolicyEgressPeer is not supported; " + ignoreMsg // example raising this
	// warning: tests/anp_and_banp_using_networks_and_nodes_test
)
