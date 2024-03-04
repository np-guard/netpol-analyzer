package connlist

import (
	"path/filepath"
	"testing"

	"github.com/np-guard/netpol-analyzer/pkg/internal/testutils"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/fsscanner"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/parser"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"

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
	lenEgressExposedConns  int
}

// TestExposureBehavior tests the behavior of exposure analysis
func TestExposureBehavior(t *testing.T) {
	t.Parallel()
	cases := []struct {
		testName                       string
		numOfParsingErrs               int
		expectedNumRepresentativePeers int
		expectedLenOfExposedPeerList   int
		wl1ExpDataInfo                 expectedPeerResultInfo
		wl2ExpDataInfo                 expectedPeerResultInfo
	}{
		{
			testName:                       "test_allow_all",
			expectedNumRepresentativePeers: 0,
			expectedLenOfExposedPeerList:   1,
			// workload 1 unsecure exposed to all other end-points in the world
			wl1ExpDataInfo: expectedPeerResultInfo{
				isIngressProtected:     true,
				isEgressProtected:      true,
				lenIngressExposedConns: 1, // entire cluster conns
				lenEgressExposedConns:  1,
			},
		},
		{
			testName:                       "test_allow_all_in_cluster",
			expectedNumRepresentativePeers: 0,
			expectedLenOfExposedPeerList:   1,
			// workload 1 unsecure exposed to all other end-points in the cluster
			wl1ExpDataInfo: expectedPeerResultInfo{
				isIngressProtected:     true,
				isEgressProtected:      true,
				lenIngressExposedConns: 1,
				lenEgressExposedConns:  1,
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
				lenEgressExposedConns:  0,
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
			// workload 1 is protected and connected with known namespace in the cluster on both directions (exposed securely)
			// workload 2 is not protected at all (unsecure exposed)
			wl2ExpDataInfo: expectedPeerResultInfo{
				isIngressProtected:     false,
				isEgressProtected:      false,
				lenIngressExposedConns: 0,
				lenEgressExposedConns:  0,
			},
		},
		{
			testName:                       "test_multiple_unmatched_rules",
			expectedNumRepresentativePeers: 3,
			expectedLenOfExposedPeerList:   1,
			// workload 1 is protected by ingress netpol but exposed to unknown namespaces; not protected on egress
			wl1ExpDataInfo: expectedPeerResultInfo{
				isIngressProtected:     true,
				isEgressProtected:      false,
				lenIngressExposedConns: 3,
				lenEgressExposedConns:  0,
			},
		},
		{
			testName:                       "test_same_unmatched_rule_in_ingress_egress",
			expectedNumRepresentativePeers: 1,
			expectedLenOfExposedPeerList:   1,
			// workload 1 is exposed unsecure to same unknown namespace on both directions
			wl1ExpDataInfo: expectedPeerResultInfo{
				isIngressProtected:     true,
				isEgressProtected:      true,
				lenIngressExposedConns: 2, // one to the unmatched rule and other to the entire cluster (no containment)
				lenEgressExposedConns:  1,
			},
		},
		{
			testName:                       "test_with_no_netpols",
			numOfParsingErrs:               1, // no netpols
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
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.testName, func(t *testing.T) {
			t.Parallel()
			pe := buildPolicyEngineWithExposureAnalysis(t, tt.testName, tt.numOfParsingErrs)
			// get real peers
			peerList, err := pe.GetPeersList()
			require.Nil(t, err, "test %q: error getting peer list", tt.testName)
			representativePeers := pe.GetRepresentativePeersList()
			require.Equal(t, tt.expectedNumRepresentativePeers, len(representativePeers),
				"test %q: mismatch in number of representative peers", tt.testName)
			peerList = append(peerList, representativePeers...)
			peers := convertEvalPeersToConnlistPeer(peerList)
			ca := NewConnlistAnalyzer(WithExposureAnalysis())
			_, exposureMap, err := ca.getConnectionsBetweenPeers(pe, peers)
			require.Nil(t, err, "test %q: error getting connections between peers", tt.testName)
			exposedPeers := buildExposedPeerListFromExposureMap(exposureMap)
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

// todo handle error
func buildPolicyEngineWithExposureAnalysis(t *testing.T, dirName string, numOfParsingErrs int) *eval.PolicyEngine {
	testDir := testutils.GetTestDirPath(filepath.Join(exposureAnalysisTestsDirName, dirName))
	rList, errs := fsscanner.GetResourceInfosFromDirPath([]string{testDir}, false, false)
	require.Empty(t, errs, "test %q: nonempty errs list returned from the fsscanner", dirName)
	k8sObjects, fpErrs := parser.ResourceInfoListToK8sObjectsList(rList, nil, true)
	require.Equal(t, numOfParsingErrs, len(fpErrs),
		"test %q: mismatch in length of errors list returned from the parser", dirName)
	pe := eval.NewPolicyEngineWithOptions(true)
	err := pe.AddObjects(k8sObjects)
	require.Empty(t, err, "test %q: error adding objects to the policy engine", dirName)
	return pe
}

func checkExpectedVsActualData(t *testing.T, testName string, actualExp ExposedPeer, expectedData expectedPeerResultInfo) {
	require.Equal(t, expectedData.isEgressProtected, actualExp.IsProtectedByEgressNetpols(),
		"test: %q, mismatch in is egress protected for peer %q", testName, actualExp.ExposedPeer().String())
	require.Equal(t, expectedData.isIngressProtected, actualExp.IsProtectedByIngressNetpols(),
		"test: %q, mismatch in is ingress protected for peer %q", testName, actualExp.ExposedPeer().String())
	require.Equal(t, expectedData.lenIngressExposedConns, len(actualExp.IngressExposure()),
		"test: %q, mismatch in length of ingress exposure slice for peer %q", testName, actualExp.ExposedPeer().String())
	require.Equal(t, expectedData.lenEgressExposedConns, len(actualExp.EgressExposure()),
		"test: %q, mismatch in length of egress exposure slice for peer %q", testName, actualExp.ExposedPeer().String())
}
