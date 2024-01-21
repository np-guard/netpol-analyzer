package connlist

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"

	"github.com/np-guard/netpol-analyzer/pkg/internal/testutils"
	"github.com/np-guard/netpol-analyzer/pkg/logger"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/fsscanner"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/parser"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// file for testing func buildExposedPeerListFromExposureMap

// getPeersFromFilePath returns workload peers from file, peers used for testing
func getPeersFromFilePath(t *testing.T) (wl1, wl2 eval.Peer) {
	workload1Name := "workload-a"
	peersFile := testutils.GetTestDirPath(filepath.Join("minimal_test_in_ns", "namespace_and_deployments.yaml"))
	rList, _ := fsscanner.GetResourceInfosFromDirPath([]string{peersFile}, false, false)
	objects, _ := parser.ResourceInfoListToK8sObjectsList(rList, logger.NewDefaultLogger(), false)
	pe, err := eval.NewPolicyEngineWithObjects(objects)
	require.Empty(t, err, "error in generating new policy engine; getPeersFromFilePath")
	peers, err := pe.GetPeersList()
	require.Empty(t, err, "error getting peer list; getPeersFromFilePath")
	if peers[0].Name() == workload1Name {
		return peers[0], peers[1]
	}
	return peers[1], peers[0]
}

// expectedPeerResultInfo contains data on the exposure result for the peer
type expectedPeerResultInfo struct {
	isIngProtected     bool
	isEgProtected      bool
	lenIngExposedConns int
	lenEgExposedConns  int
}

var allConns *common.ConnectionSet = &common.ConnectionSet{
	AllowAll:         true,
	AllowedProtocols: nil,
}

var tcpConn *common.ConnectionSet = &common.ConnectionSet{
	AllowAll: false,
	AllowedProtocols: map[v1.Protocol]*common.PortSet{
		v1.ProtocolTCP: {
			Ports:              common.CanonicalIntervalSet{},
			NamedPorts:         nil,
			ExcludedNamedPorts: nil,
		},
	},
}

var notProtectedPeer *peerExposureData = &peerExposureData{
	isIngressProtected: false,
	isEgressProtected:  false,
	ingressExposure:    nil,
	egressExposure:     nil,
}

var anyNsExposureAllConns *xgressExposure = &xgressExposure{
	exposedToEntireCluster: true,
	namespaceLabels:        nil,
	podLabels:              nil,
	potentialConn:          allConns,
}

var anyNsExposureTCP *xgressExposure = &xgressExposure{
	exposedToEntireCluster: true,
	namespaceLabels:        nil,
	podLabels:              nil,
	potentialConn:          tcpConn,
}

var specificNsExposureAllConns *xgressExposure = &xgressExposure{
	exposedToEntireCluster: false,
	namespaceLabels:        map[string]string{"foo": "managed"},
	podLabels:              nil,
	potentialConn:          allConns,
}

var specificNsExposureTCP *xgressExposure = &xgressExposure{
	exposedToEntireCluster: false,
	namespaceLabels:        map[string]string{"access": "true"},
	podLabels:              nil,
	potentialConn:          tcpConn,
}

var exposedToAnyNs *peerExposureData = &peerExposureData{
	isIngressProtected: true,
	isEgressProtected:  true,
	ingressExposure:    []*xgressExposure{anyNsExposureAllConns},
	egressExposure:     []*xgressExposure{anyNsExposureAllConns},
}

var exposedIngressToNsWithLabel *peerExposureData = &peerExposureData{
	isIngressProtected: true,
	isEgressProtected:  false,
	ingressExposure:    []*xgressExposure{specificNsExposureAllConns},
	egressExposure:     nil,
}

var multipleExposeOnIngress *peerExposureData = &peerExposureData{
	isIngressProtected: true,
	isEgressProtected:  true,
	ingressExposure:    []*xgressExposure{specificNsExposureAllConns, specificNsExposureTCP},
	egressExposure:     []*xgressExposure{specificNsExposureAllConns},
}

var multipleExposeToEntireCluster *peerExposureData = &peerExposureData{
	isIngressProtected: true,
	isEgressProtected:  false,
	ingressExposure:    []*xgressExposure{anyNsExposureAllConns, anyNsExposureTCP},
	egressExposure:     nil,
}

func TestExposedPeersListFromMap(t *testing.T) {
	// peers for testing
	wl1, wl2 := getPeersFromFilePath(t)
	t.Parallel()
	cases := []struct {
		name string
		// exposureMap
		exMap exposureMap
		// expected results
		lenResult      int
		wl1ExpDataInfo expectedPeerResultInfo
		wl2ExpDataInfo expectedPeerResultInfo
	}{
		{
			name: "both peers are not protected",
			exMap: exposureMap{
				wl1: notProtectedPeer,
				wl2: notProtectedPeer,
			},
			lenResult: 2,
			wl1ExpDataInfo: expectedPeerResultInfo{
				isIngProtected:     false,
				isEgProtected:      false,
				lenIngExposedConns: 0,
				lenEgExposedConns:  0,
			},
			wl2ExpDataInfo: expectedPeerResultInfo{
				isIngProtected:     false,
				isEgProtected:      false,
				lenIngExposedConns: 0,
				lenEgExposedConns:  0,
			},
		},
		{
			name: "one peer is not protected, other allows all",
			exMap: exposureMap{
				wl1: notProtectedPeer,
				wl2: exposedToAnyNs,
			},
			lenResult: 2,
			wl1ExpDataInfo: expectedPeerResultInfo{
				isIngProtected:     false,
				isEgProtected:      false,
				lenIngExposedConns: 0,
				lenEgExposedConns:  0,
			},
			wl2ExpDataInfo: expectedPeerResultInfo{
				isIngProtected:     true,
				isEgProtected:      true,
				lenIngExposedConns: 1,
				lenEgExposedConns:  1,
			},
		},
		{
			name: "one peer is exposed on ingress to a namespace with label",
			exMap: exposureMap{
				wl1: exposedIngressToNsWithLabel,
				wl2: notProtectedPeer,
			},
			lenResult: 2,
			wl1ExpDataInfo: expectedPeerResultInfo{
				isIngProtected:     true,
				isEgProtected:      false,
				lenIngExposedConns: 1,
				lenEgExposedConns:  0,
			},
			wl2ExpDataInfo: expectedPeerResultInfo{
				isIngProtected:     false,
				isEgProtected:      false,
				lenIngExposedConns: 0,
				lenEgExposedConns:  0,
			},
		},
		{
			name: "specific ingress exposure contained in general one",
			exMap: exposureMap{
				wl1: notProtectedPeer,
				wl2: &peerExposureData{
					isIngressProtected: true,
					isEgressProtected:  false,
					ingressExposure:    []*xgressExposure{anyNsExposureAllConns, specificNsExposureAllConns},
					egressExposure:     nil,
				},
			},
			lenResult: 2,
			wl1ExpDataInfo: expectedPeerResultInfo{
				isIngProtected:     false,
				isEgProtected:      false,
				lenIngExposedConns: 0,
				lenEgExposedConns:  0,
			},
			wl2ExpDataInfo: expectedPeerResultInfo{
				isIngProtected:     true,
				isEgProtected:      false,
				lenIngExposedConns: 1,
				lenEgExposedConns:  0,
			},
		},
		{
			name: "peer is exposed on egress to specific ns, on ingress to two unrelated namespaces",
			exMap: exposureMap{
				wl1: multipleExposeOnIngress,
			},
			lenResult: 1,
			wl1ExpDataInfo: expectedPeerResultInfo{
				isIngProtected:     true,
				isEgProtected:      true,
				lenIngExposedConns: 2,
				lenEgExposedConns:  1,
			},
			wl2ExpDataInfo: expectedPeerResultInfo{},
		},
		{
			name: "peer has two entries to entire cluster expecting to get one",
			exMap: exposureMap{
				wl2: multipleExposeToEntireCluster,
			},
			lenResult:      1,
			wl1ExpDataInfo: expectedPeerResultInfo{},
			wl2ExpDataInfo: expectedPeerResultInfo{
				isIngProtected:     true,
				isEgProtected:      false,
				lenIngExposedConns: 1,
				lenEgExposedConns:  0,
			},
		},
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			exposedPeers := buildExposedPeerListFromExposureMap(tt.exMap)
			require.Equal(t, tt.lenResult, len(exposedPeers),
				"test %q, mismatch in number of exposed peers, expected %d, got %d", tt.name, tt.lenResult, len(exposedPeers))
			for _, ep := range exposedPeers {
				require.Contains(t, []string{wl1.Name(), wl2.Name()}, ep.ExposedPeer().Name(), "test: %q, unexpected exposed peer name %q",
					tt.name, ep.ExposedPeer().String())
				if ep.ExposedPeer().String() == wl1.String() {
					checkExpectedVsActualData(t, tt.name, ep, tt.wl1ExpDataInfo)
				} else {
					checkExpectedVsActualData(t, tt.name, ep, tt.wl2ExpDataInfo)
				}
			}
		})
	}
}

func checkExpectedVsActualData(t *testing.T, testName string, actualExp ExposedPeer, expectedData expectedPeerResultInfo) {
	require.Equal(t, actualExp.IsProtectedByEgressNetpols(), expectedData.isEgProtected,
		"test: %q, mismatch in is egress protected for peer %q", testName, actualExp.ExposedPeer().String())
	require.Equal(t, actualExp.IsProtectedByIngressNetpols(), expectedData.isIngProtected,
		"test: %q, mismatch in is ingress protected for peer %q", testName, actualExp.ExposedPeer().String())
	require.Equal(t, len(actualExp.IngressExposure()), expectedData.lenIngExposedConns,
		"test: %q, mismatch in length of ingress exposure slice for peer %q", testName, actualExp.ExposedPeer().String())
	require.Equal(t, len(actualExp.EgressExposure()), expectedData.lenEgExposedConns,
		"test: %q, mismatch in length of egress exposure slice for peer %q", testName, actualExp.ExposedPeer().String())
}
