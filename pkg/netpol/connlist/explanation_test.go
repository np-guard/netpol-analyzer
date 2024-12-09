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
	//t.Parallel()
	for _, tt := range explainTests {
		tt := tt
		t.Run(tt.testDirName, func(t *testing.T) {
			//t.Parallel()
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
	// {
	// 	testDirName: "anp_test_10",
	// },
	{
		testDirName:   "anp_banp_blog_demo",
		focusWorkload: "my-monitoring",
	},
	{
		testDirName: "anp_banp_blog_demo_2",
		//focusWorkload: "my-monitoring",
	},
	// {
	// 	testDirName: "ipblockstest",
	// },
	// {
	// 	testDirName: "onlineboutique",
	// },
	// {
	// 	testDirName: "anp_banp_blog_demo",
	// },
	// {
	// 	testDirName: "acs-security-demos",
	// },
	// {
	// 	testDirName:   "acs-security-demos",
	// 	focusWorkload: "ingress-controller",
	// },
}