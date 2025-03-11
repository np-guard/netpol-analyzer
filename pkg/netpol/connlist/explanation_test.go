/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package connlist

import (
	"fmt"
	"strings"
	"testing"

	"github.com/np-guard/netpol-analyzer/pkg/internal/common"
	"github.com/np-guard/netpol-analyzer/pkg/internal/output"
	"github.com/np-guard/netpol-analyzer/pkg/internal/testutils"

	"github.com/stretchr/testify/require"
)

// file for testing functionality of explainability analysis

func TestExplainFromDir(t *testing.T) {
	t.Parallel()
	for _, tt := range explainTests {
		t.Run(tt.testDirName, func(t *testing.T) {
			t.Parallel()
			pTest := prepareExplainTest(tt.testDirName, tt.focusWorkloads, tt.focusWorkloadPeers, tt.focusDirection,
				tt.focusConn, tt.explainOnly, tt.exposure)
			res, _, err := pTest.analyzer.ConnlistFromDirPath(pTest.dirPath)
			require.Nil(t, err, pTest.testInfo)
			out, err := pTest.analyzer.ConnectionsListToString(res)
			require.Nil(t, err, pTest.testInfo)
			testutils.CheckActualVsExpectedOutputMatch(t, pTest.expectedOutputFileName, out,
				pTest.testInfo, currentPkg)
		})
	}
}

func prepareExplainTest(dirName string, focusWorkloads, focusWorkloadPeers []string, focusDirection, focusConn,
	explainOnly string, exposure bool) preparedTest {
	res := preparedTest{}
	res.testName, res.expectedOutputFileName = testutils.ExplainTestNameByTestArgs(dirName,
		strings.Join(focusWorkloads, testutils.Underscore), strings.Join(focusWorkloadPeers, testutils.Underscore), focusDirection,
		focusConn, explainOnly, exposure)
	res.testInfo = fmt.Sprintf("test: %q", res.testName)
	opts := []ConnlistAnalyzerOption{WithOutputFormat(output.TextFormat), WithFocusWorkloadList(focusWorkloads),
		WithFocusWorkloadPeerList(focusWorkloadPeers), WithFocusDirection(focusDirection), WithExplanation(), WithExplainOnly(explainOnly),
		WithFocusConnection(focusConn)}
	if exposure {
		opts = append(opts, WithExposureAnalysis())
	}
	res.analyzer = NewConnlistAnalyzer(opts...)
	res.dirPath = testutils.GetTestDirPath(dirName)
	return res
}

var explainTests = []struct {
	testDirName            string
	focusWorkloads         []string
	focusDirection         string
	focusConn              string
	focusWorkloadPeers     []string
	exposure               bool
	explainOnly            string
	supportedOnLiveCluster bool
}{
	{
		testDirName: "acs-security-demos",
	},
	{
		testDirName: "anp_and_banp_using_networks_and_nodes_test",
	},
	{
		testDirName:            "anp_banp_blog_demo",
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "anp_banp_blog_demo",
		exposure:               true,
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "anp_banp_blog_demo",
		focusWorkloads:         []string{"myfoo"},
		focusDirection:         common.IngressFocusDirection,
		supportedOnLiveCluster: true,
	},
	{
		testDirName: "anp_banp_blog_demo_2",
	},
	{
		testDirName: "anp_banp_test_with_named_port_matched",
	},
	{
		testDirName: "anp_banp_test_with_named_port_unmatched",
	},
	{
		testDirName: "anp_demo",
	},
	{
		testDirName: "anp_test_10",
	},
	{
		testDirName: "demo_app_with_routes_and_ingress",
	},
	{
		testDirName:            "ipblockstest",
		supportedOnLiveCluster: true,
	},
	{
		testDirName: "k8s_ingress_test_new",
	},
	{
		testDirName: "multiple_ingress_objects_with_different_ports_new",
	},
	{
		testDirName:            "multiple_topology_resources_2",
		supportedOnLiveCluster: true,
	},
	{
		testDirName: "netpol_named_port_test",
	},
	{
		testDirName: "new_online_boutique",
	},
	{
		testDirName:            "onlineboutique",
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "onlineboutique",
		exposure:               true,
		supportedOnLiveCluster: true,
	},
	{
		testDirName: "onlineboutique_workloads_with_ingress",
	},
	{
		testDirName: "route_example_with_target_port",
	},
	{
		testDirName: "vm_example",
	},
	{
		testDirName: "vm_example",
		exposure:    true,
	},
	{
		testDirName: "exposure_allow_all_test",
		exposure:    true,
	},
	{
		testDirName: "exposure_allow_all_in_cluster_test",
		exposure:    true,
	},
	{
		testDirName: "exposure_allow_all_two_workloads_test",
	},
	{
		testDirName: "exposure_allow_all_two_workloads_test",
		exposure:    true,
	},
	{
		testDirName: "exposure_matched_and_unmatched_rules_test",
		exposure:    true,
	},
	{
		testDirName:    "exposure_matched_and_unmatched_rules_test",
		exposure:       true,
		focusWorkloads: []string{"hello-world/workload-a"},
	},
	{
		testDirName:    "exposure_matched_and_unmatched_rules_test",
		exposure:       true,
		focusWorkloads: []string{"hello-world/workload-a"},
		focusDirection: common.IngressFocusDirection,
	},
	{
		testDirName: "exposure_multiple_unmatched_rules_test",
		exposure:    true,
	},
	{
		testDirName: "exposure_to_new_namespace_conn_and_entire_cluster",
		exposure:    true,
	},
	{
		testDirName: "exposure_test_pod_exposed_only_to_representative_peers",
		exposure:    true,
	},
	{
		testDirName: "exposure_test_conn_entire_cluster_with_empty_selectors",
		exposure:    true,
	},
	{
		testDirName: "exposure_test_conn_to_all_pods_in_a_new_ns",
		exposure:    true,
	},
	{
		testDirName: "exposure_test_conn_with_only_pod_selector",
		exposure:    true,
	},
	{
		testDirName: "exposure_test_conn_with_pod_selector_in_any_ns",
		exposure:    true,
	},
	{
		testDirName: "exposure_test_with_anp_1",
		exposure:    true,
	},
	{
		testDirName: "exposure_test_with_anp_2_w_np",
		exposure:    true,
	},
	{
		testDirName: "exposure_test_with_anp_3_w_banp",
		exposure:    true,
	},
	{
		testDirName: "exposure_test_with_anp_4_entire_cluster_example",
		exposure:    true,
	},
	{
		testDirName: "exposure_test_with_anp_5_entire_cluster_example",
		exposure:    true,
	},
	{
		testDirName: "exposure_test_with_anp_6_entire_cluster_example",
		exposure:    true,
	},
	{
		testDirName: "exposure_test_with_anp_7_w_banp",
		exposure:    true,
	},
	{
		testDirName: "exposure_test_with_anp_8",
		exposure:    true,
	},
	{
		testDirName: "exposure_test_with_anp_9",
		exposure:    true,
	},
	{
		testDirName: "exposure_test_with_anp_12",
		exposure:    true,
	},
	{
		testDirName: "exposure_test_with_anp_15",
		exposure:    true,
	},
	{
		testDirName: "exposure_test_with_anp_16",
		exposure:    true,
	},
	// tests with multiple focus-workloads
	{
		testDirName:    "exposure_matched_and_unmatched_rules_test",
		exposure:       true,
		focusWorkloads: []string{"hello-world/workload-a", "workload-b"},
		focusDirection: common.IngressFocusDirection,
	},
	{
		testDirName:            "anp_banp_blog_demo",
		focusWorkloads:         []string{"mymonitoring", "mybaz"},
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "anp_banp_blog_demo",
		focusWorkloads:         []string{"mymonitoring"},
		focusWorkloadPeers:     []string{"myfoo"},
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "anp_banp_blog_demo",
		focusWorkloads:         []string{"myfoo", "mybar"},
		focusWorkloadPeers:     []string{"mybaz", "mymonitoring"},
		focusDirection:         common.EgressFocusDirection,
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "anp_banp_blog_demo",
		explainOnly:            common.ExplainOnlyDeny,
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "anp_banp_blog_demo",
		focusWorkloads:         []string{"mymonitoring"},
		focusWorkloadPeers:     []string{"myfoo"},
		explainOnly:            common.ExplainOnlyAllow,
		supportedOnLiveCluster: true,
	},
	{
		testDirName:            "anp_banp_blog_demo",
		focusWorkloads:         []string{"mymonitoring"},
		focusWorkloadPeers:     []string{"myfoo"},
		explainOnly:            common.ExplainOnlyAllow,
		focusDirection:         common.EgressFocusDirection,
		supportedOnLiveCluster: true,
	},
	{
		testDirName: "acs-security-demos",
		focusConn:   "udp-5353",
		explainOnly: common.ExplainOnlyDeny,
	},
	{
		testDirName:            "anp_banp_blog_demo",
		focusWorkloads:         []string{"mymonitoring"},
		focusWorkloadPeers:     []string{"myfoo"},
		explainOnly:            common.ExplainOnlyAllow,
		focusDirection:         common.EgressFocusDirection,
		focusConn:              "tcp-80",
		supportedOnLiveCluster: true,
	},
	{
		testDirName: "acs-security-demos",
		focusConn:   "tcp-8080",
		exposure:    true,
	},
}
