/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package connlist

import (
	"testing"

	v1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/np-guard/netpol-analyzer/pkg/internal/testutils"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"

	"github.com/stretchr/testify/require"
)

// file for testing functionality of exposure analysis

// all tests' dir in this file has one or two of these workloads names
const (
	exposureAnalysisTestsDirName = "exposure_analysis_tests"
	wl1Name                      = "workload-a"
	wl2Name                      = "workload-b"
)

// expectedPeerResultInfo contains data on the exposure result for the peer
type expectedPeerResultInfo struct {
	isIngressProtected     bool
	isEgressProtected      bool
	lenIngressExposedConns int
	ingressExp             []*xgressExposure
	lenEgressExposedConns  int
	egressExp              []*xgressExposure
}

var peerExposedToEntireCluster *xgressExposure = &xgressExposure{
	exposedToEntireCluster: true,
	potentialConn:          common.MakeConnectionSet(true),
}

var peerExposedToEntireClusterOnTCP8050 *xgressExposure = &xgressExposure{
	exposedToEntireCluster: true,
	potentialConn:          newTCPConnWithPorts([]int{8050}),
}

var matchExpression []metaV1.LabelSelectorRequirement = []metaV1.LabelSelectorRequirement{{Key: "foo.com/managed-state",
	Operator: metaV1.LabelSelectorOpIn, Values: []string{"managed"}}}

func newTCPConnWithPorts(ports []int) *common.ConnectionSet {
	conn := common.MakeConnectionSet(false)
	portSet := common.MakePortSet(false)
	for i := range ports {
		portSet.AddPort(intstr.FromInt(ports[i]))
	}
	conn.AddConnection(v1.ProtocolTCP, portSet)
	return conn
}

func newExpDataWithLabelAndTCPConn(nsSel, podSel metaV1.LabelSelector, ports []int) *xgressExposure {
	conn := common.MakeConnectionSet(true)
	if len(ports) > 0 {
		conn = newTCPConnWithPorts(ports)
	}
	return &xgressExposure{
		exposedToEntireCluster: false,
		namespaceLabels:        nsSel,
		podLabels:              podSel,
		potentialConn:          conn,
	}
}

// TestExposureBehavior tests the behavior of exposure analysis
func TestExposureBehavior(t *testing.T) {
	t.Parallel()
	cases := []struct {
		testName                       string
		expectedNumRepresentativePeers int
		expectedLenOfExposedPeerList   int
		wl1ExpDataInfo                 expectedPeerResultInfo
		wl2ExpDataInfo                 expectedPeerResultInfo
	}{
		{
			testName:                       "test_allow_all", // only workload-a in manifests
			expectedNumRepresentativePeers: 0,
			expectedLenOfExposedPeerList:   1,
			// workload 1 unsecure exposed to all other end-points in the world
			wl1ExpDataInfo: expectedPeerResultInfo{
				isIngressProtected:     true,
				isEgressProtected:      true,
				lenIngressExposedConns: 1, // entire cluster conns
				ingressExp: []*xgressExposure{
					peerExposedToEntireCluster,
				},
				lenEgressExposedConns: 1,
				egressExp: []*xgressExposure{
					peerExposedToEntireCluster,
				},
			},
		},
		{
			testName:                       "test_allow_all_in_cluster", // only workload-a in manifests
			expectedNumRepresentativePeers: 0,
			expectedLenOfExposedPeerList:   1,
			// workload 1 unsecure exposed to all other end-points in the cluster
			wl1ExpDataInfo: expectedPeerResultInfo{
				isIngressProtected:     true,
				isEgressProtected:      true,
				lenIngressExposedConns: 1,
				lenEgressExposedConns:  1,
				ingressExp: []*xgressExposure{
					peerExposedToEntireClusterOnTCP8050,
				},
				egressExp: []*xgressExposure{
					peerExposedToEntireCluster,
				},
			},
		},
		{
			testName:                       "test_matched_and_unmatched_rules",
			expectedNumRepresentativePeers: 1,
			expectedLenOfExposedPeerList:   2,
			// workload 1 is protected only on ingress direction and exposed unsecure to entire cluster
			wl1ExpDataInfo: expectedPeerResultInfo{
				isIngressProtected:     true,
				isEgressProtected:      false,
				lenIngressExposedConns: 1, // connection to unknown dst is contained in entire cluster's conn
				ingressExp: []*xgressExposure{
					peerExposedToEntireClusterOnTCP8050,
				},
				lenEgressExposedConns: 0,
			},
			// workload 2 is not protected at all (unsecure exposed)
			wl2ExpDataInfo: expectedPeerResultInfo{
				isIngressProtected:     false,
				isEgressProtected:      false,
				lenIngressExposedConns: 0,
				lenEgressExposedConns:  0,
			},
		},
		{
			testName:                       "test_new_namespace_conn_and_entire_cluster",
			expectedNumRepresentativePeers: 1,
			expectedLenOfExposedPeerList:   2,
			// workload 1 is protected only on ingress direction and exposed unsecure to entire cluster on TCP 8050
			// and another namespace with connection different (additional) than the conn with the entire cluster
			wl1ExpDataInfo: expectedPeerResultInfo{
				isIngressProtected:     true,
				isEgressProtected:      false,
				lenIngressExposedConns: 2,
				ingressExp: []*xgressExposure{
					peerExposedToEntireClusterOnTCP8050,
					newExpDataWithLabelAndTCPConn(metaV1.LabelSelector{MatchExpressions: matchExpression}, metaV1.LabelSelector{}, []int{8050, 8090}),
				},
				lenEgressExposedConns: 0,
			},
			// workload 2 is not protected at all (unsecure exposed)
			wl2ExpDataInfo: expectedPeerResultInfo{
				isIngressProtected:     false,
				isEgressProtected:      false,
				lenIngressExposedConns: 0,
				lenEgressExposedConns:  0,
			},
		},
		{
			testName:                       "test_only_matched_rules",
			expectedNumRepresentativePeers: 0,
			expectedLenOfExposedPeerList:   1,
			// workload 1 is protected and connected with only known namespaces in the cluster on both directions
			// workload 2 is not protected at all (unsecure exposed)
			wl2ExpDataInfo: expectedPeerResultInfo{
				isIngressProtected:     false,
				isEgressProtected:      false,
				lenIngressExposedConns: 0,
				lenEgressExposedConns:  0,
			},
		},
		{
			testName:                       "test_multiple_unmatched_rules", // only workload-a in manifests
			expectedNumRepresentativePeers: 3,
			expectedLenOfExposedPeerList:   1,
			// workload 1 is protected by ingress netpol but exposed to unknown namespaces; not protected on egress
			wl1ExpDataInfo: expectedPeerResultInfo{
				isIngressProtected:     true,
				isEgressProtected:      false,
				lenIngressExposedConns: 3,
				ingressExp: []*xgressExposure{
					newExpDataWithLabelAndTCPConn(metaV1.LabelSelector{MatchExpressions: matchExpression}, metaV1.LabelSelector{}, []int{8050}),
					newExpDataWithLabelAndTCPConn(metaV1.LabelSelector{MatchLabels: map[string]string{"release": "stable"}},
						metaV1.LabelSelector{}, []int{}),
					newExpDataWithLabelAndTCPConn(metaV1.LabelSelector{MatchLabels: map[string]string{"effect": "NoSchedule"}},
						metaV1.LabelSelector{}, []int{8050}),
				},
				lenEgressExposedConns: 0,
			},
		},
		{
			testName:                       "test_with_no_netpols", // only workload-a in manifests
			expectedNumRepresentativePeers: 0,
			expectedLenOfExposedPeerList:   1,
			// workload 1 is not protected by any netpol
			wl1ExpDataInfo: expectedPeerResultInfo{
				isIngressProtected:     false,
				isEgressProtected:      false,
				lenIngressExposedConns: 0,
				lenEgressExposedConns:  0,
			},
		},
		{
			testName:                       "test_allow_ingress_deny_egress", // only workload-a in manifests
			expectedNumRepresentativePeers: 0,
			expectedLenOfExposedPeerList:   1,
			// workload 1 is exposed to entire cluter on ingress
			wl1ExpDataInfo: expectedPeerResultInfo{
				isIngressProtected:     true,
				isEgressProtected:      true,
				lenIngressExposedConns: 1,
				ingressExp: []*xgressExposure{
					peerExposedToEntireCluster,
				},
				lenEgressExposedConns: 0,
			},
		},
		{
			testName:                       "test_allow_egress_deny_ingress", // only workload-a in manifests
			expectedNumRepresentativePeers: 0,
			expectedLenOfExposedPeerList:   1,
			// workload 1 is exposed to entire cluter on egress
			wl1ExpDataInfo: expectedPeerResultInfo{
				isIngressProtected:     true,
				isEgressProtected:      true,
				lenIngressExposedConns: 0,
				lenEgressExposedConns:  1,
				egressExp: []*xgressExposure{
					peerExposedToEntireCluster,
				},
			},
		},
		{
			testName:                       "test_conn_entire_cluster_with_empty_selectors", // only workload-a in manifests
			expectedNumRepresentativePeers: 0,
			expectedLenOfExposedPeerList:   1,
			// workload 1 is exposed to entire cluster on ingress and egress
			wl1ExpDataInfo: expectedPeerResultInfo{
				isIngressProtected:     true,
				isEgressProtected:      true,
				lenIngressExposedConns: 1,
				lenEgressExposedConns:  1,
				ingressExp: []*xgressExposure{
					peerExposedToEntireClusterOnTCP8050,
				},
				egressExp: []*xgressExposure{
					peerExposedToEntireCluster,
				},
			},
		},
		{
			testName:                       "test_conn_to_all_pods_in_a_new_ns", // only workload-a in manifests
			expectedNumRepresentativePeers: 1,
			expectedLenOfExposedPeerList:   1,
			// workload-a is exposed to entire cluster on egress, to a rep. peer on ingress
			wl1ExpDataInfo: expectedPeerResultInfo{
				isIngressProtected:     true,
				isEgressProtected:      true,
				lenIngressExposedConns: 1,
				lenEgressExposedConns:  1,
				ingressExp: []*xgressExposure{
					newExpDataWithLabelAndTCPConn(metaV1.LabelSelector{MatchLabels: map[string]string{common.K8sNsNameLabelKey: "backend"}},
						metaV1.LabelSelector{}, []int{8050}),
				},
				egressExp: []*xgressExposure{
					peerExposedToEntireCluster,
				},
			},
		},
		{
			testName:                       "test_conn_with_new_pod_selector_and_ns_selector", // only workload-a in manifests
			expectedNumRepresentativePeers: 1,
			expectedLenOfExposedPeerList:   1,
			wl1ExpDataInfo: expectedPeerResultInfo{
				isIngressProtected:     true,
				isEgressProtected:      false,
				lenIngressExposedConns: 1,
				lenEgressExposedConns:  0,
				ingressExp: []*xgressExposure{
					newExpDataWithLabelAndTCPConn(metaV1.LabelSelector{MatchLabels: map[string]string{"effect": "NoSchedule"}},
						metaV1.LabelSelector{MatchLabels: map[string]string{"role": "monitoring"}}, []int{8050}),
				},
			},
		},
		{
			testName:                       "test_conn_with_only_pod_selector", // only workload-a in manifests
			expectedNumRepresentativePeers: 1,
			expectedLenOfExposedPeerList:   1,
			wl1ExpDataInfo: expectedPeerResultInfo{
				isIngressProtected:     true,
				isEgressProtected:      false,
				lenIngressExposedConns: 1,
				lenEgressExposedConns:  0,
				ingressExp: []*xgressExposure{
					newExpDataWithLabelAndTCPConn(metaV1.LabelSelector{MatchLabels: map[string]string{common.K8sNsNameLabelKey: "hello-world"}},
						metaV1.LabelSelector{MatchLabels: map[string]string{"role": "monitoring"}},
						[]int{8050}),
				},
			},
		},
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.testName, func(t *testing.T) {
			t.Parallel()
			ca := NewConnlistAnalyzer(WithExposureAnalysis())
			testDir := testutils.GetTestDirPath(tt.testName)
			_, _, err := ca.ConnlistFromDirPath(testDir)
			require.Empty(t, err, "test %q: err returned from the ConnlistFromDirPath", tt.testName)
			exposedPeers := ca.ExposedPeers()
			require.Equal(t, tt.expectedLenOfExposedPeerList, len(exposedPeers),
				"test %q: mismatch in length of exposedPeer list", tt.testName)
			for _, ep := range exposedPeers {
				require.Contains(t, []string{wl1Name, wl2Name}, ep.ExposedPeer().Name(), "test: %q, unexpected exposed peer name %q",
					tt.testName, ep.ExposedPeer().String())
				if ep.ExposedPeer().Name() == wl1Name {
					checkExpectedVsActualData(t, tt.testName, ep, tt.wl1ExpDataInfo)
				} else {
					checkExpectedVsActualData(t, tt.testName, ep, tt.wl2ExpDataInfo)
				}
			}
		})
	}
}

func checkExpectedVsActualData(t *testing.T, testName string, actualExp ExposedPeer, expectedData expectedPeerResultInfo) {
	require.Equal(t, expectedData.isEgressProtected, actualExp.IsProtectedByEgressNetpols(),
		"test: %q, mismatch in is egress protected for peer %q", testName, actualExp.ExposedPeer().String())
	require.Equal(t, expectedData.isIngressProtected, actualExp.IsProtectedByIngressNetpols(),
		"test: %q, mismatch in is ingress protected for peer %q", testName, actualExp.ExposedPeer().String())
	require.Equal(t, expectedData.lenIngressExposedConns, len(actualExp.IngressExposure()),
		"test: %q, mismatch in length of ingress exposure slice for peer %q", testName, actualExp.ExposedPeer().String())
	for i := range expectedData.ingressExp {
		require.Contains(t, actualExp.IngressExposure(), expectedData.ingressExp[i],
			"test: %q, expected ingress data %v is not contained in actual results", testName, expectedData.ingressExp[i])
	}
	require.Equal(t, expectedData.lenEgressExposedConns, len(actualExp.EgressExposure()),
		"test: %q, mismatch in length of egress exposure slice for peer %q", testName, actualExp.ExposedPeer().String())
	for i := range expectedData.egressExp {
		require.Contains(t, actualExp.EgressExposure(), expectedData.egressExp[i],
			"test: %q, expected egress data %v is not contained in actual results", testName, expectedData.egressExp[i])
	}
}
