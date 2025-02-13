/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package connlist

import (
	"fmt"
	"testing"

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
			pTest := prepareExplainTest(tt.testDirName, tt.focusWorkload)
			res, _, err := pTest.analyzer.ConnlistFromDirPath(pTest.dirPath)
			require.Nil(t, err, pTest.testInfo)
			out, err := pTest.analyzer.ConnectionsListToString(res)
			require.Nil(t, err, pTest.testInfo)
			testutils.CheckActualVsExpectedOutputMatch(t, pTest.expectedOutputFileName, out,
				pTest.testInfo, currentPkg)
		})
	}
}

func prepareExplainTest(dirName, focusWorkload string) preparedTest {
	res := preparedTest{}
	res.testName, res.expectedOutputFileName = testutils.ExplainTestNameByTestArgs(dirName, focusWorkload)
	res.testInfo = fmt.Sprintf("test: %q", res.testName)
	cAnalyzer := NewConnlistAnalyzer(WithOutputFormat(output.TextFormat), WithFocusWorkload(focusWorkload), WithExplanation())
	res.analyzer = cAnalyzer
	res.dirPath = testutils.GetTestDirPath(dirName)
	return res
}

var explainTests = []struct {
	testDirName   string
	focusWorkload string
}{
	{
		testDirName: "acs-security-demos",
	},
	{
		testDirName: "anp_and_banp_using_networks_and_nodes_test",
	},
	{
		testDirName: "anp_banp_blog_demo",
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
		testDirName: "ipblockstest",
	},
	{
		testDirName: "k8s_ingress_test_new",
	},
	{
		testDirName: "multiple_ingress_objects_with_different_ports_new",
	},
	{
		testDirName: "multiple_topology_resources_2",
	},
	{
		testDirName: "netpol_named_port_test",
	},
	{
		testDirName: "new_online_boutique",
	},
	{
		testDirName: "onlineboutique",
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
}
