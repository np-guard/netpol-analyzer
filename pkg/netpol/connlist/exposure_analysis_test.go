package connlist

import (
	"path/filepath"
	"testing"

	v1 "k8s.io/api/core/v1"
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
	potentialConn:          newTCPConnWithPort(8050),
}

func newTCPConnWithPort(port int) *common.ConnectionSet {
	conn := common.MakeConnectionSet(false)
	portSet := common.MakePortSet(false)
	portSet.AddPort(intstr.FromInt(port))
	conn.AddConnection(v1.ProtocolTCP, portSet)
	return conn
}

func newExpDataWithLabelAndTCPConn(key, val string, portNum int) *xgressExposure {
	conn := common.MakeConnectionSet(true)
	if portNum != -1 {
		conn = newTCPConnWithPort(portNum)
	}
	return &xgressExposure{
		exposedToEntireCluster: false,
		namespaceLabels:        map[string]string{key: val},
		podLabels:              map[string]string{},
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
					newExpDataWithLabelAndTCPConn("foo.com/managed-state", "managed", 8050),
					newExpDataWithLabelAndTCPConn("release", "stable", -1),
					newExpDataWithLabelAndTCPConn("effect", "NoSchedule", 8050),
				},
				lenEgressExposedConns: 0,
			},
		},
		{
			testName:                       "test_with_no_netpols",  // only workload-a in manifests
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
			testName:                       "test_allow_ingress_deny_egress",
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
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.testName, func(t *testing.T) {
			t.Parallel()
			ca := NewConnlistAnalyzer(WithExposureAnalysis())
			testDir := testutils.GetTestDirPath(filepath.Join(exposureAnalysisTestsDirName, tt.testName))
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
