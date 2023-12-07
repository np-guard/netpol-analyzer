package ingressanalyzer

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/np-guard/netpol-analyzer/pkg/internal/testutils"
	"github.com/np-guard/netpol-analyzer/pkg/logger"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/fsscanner"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/parser"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
)

const currentPkg = testutils.Ingressanalyzer

// helping func - scans the directory objects and returns the ingress analyzer built from them
func getIngressAnalyzerFromDirObjects(t *testing.T, testName, dirName string, processingErrsNum int) *IngressAnalyzer {
	path := filepath.Join(testutils.GetTestsDir(currentPkg), dirName)
	rList, _ := fsscanner.GetResourceInfosFromDirPath([]string{path}, true, false)
	objects, fpErrs := parser.ResourceInfoListToK8sObjectsList(rList, logger.NewDefaultLogger(), false)
	require.Len(t, fpErrs, processingErrsNum, "test: %q, expected %d processing errors but got %d",
		testName, processingErrsNum, len(fpErrs))
	pe, err := eval.NewPolicyEngineWithObjects(objects)
	require.Empty(t, err, "test: %q", testName)
	ia, err := NewIngressAnalyzerWithObjects(objects, pe, logger.NewDefaultLogger(), false)
	require.Empty(t, err, "test: %q", testName)
	return ia
}

func TestRouteMappingToServices(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name                               string
		routeName                          string
		routeNamespace                     string
		dirName                            string
		processingErrorsNum                int
		expectedLengthOfRouteToServicesMap int
		expectedNumOfRoutesInNamespace     int
		expectedNumOfRouteServices         int
	}{
		{
			routeName:                          "webapp",
			routeNamespace:                     "frontend",
			dirName:                            "acs_security_frontend_demos",
			processingErrorsNum:                0,
			expectedLengthOfRouteToServicesMap: 1,
			expectedNumOfRoutesInNamespace:     2,
			expectedNumOfRouteServices:         1,
		},
	}
	for _, tt := range cases {
		tt := tt
		testName := "route_" + tt.routeNamespace + "_" + tt.routeName
		t.Run(testName, func(t *testing.T) {
			t.Parallel()
			ia := getIngressAnalyzerFromDirObjects(t, testName, tt.dirName, tt.processingErrorsNum)
			require.Len(t, ia.routesToServicesMap, tt.expectedLengthOfRouteToServicesMap,
				"test %q, mismatch in RouteToServicesMap length, expected %d, got %d", tt.name, tt.expectedLengthOfRouteToServicesMap,
				len(ia.routesToServicesMap))
			require.Len(t, ia.routesToServicesMap[tt.routeNamespace], tt.expectedNumOfRoutesInNamespace,
				"test %q, mismatch in number of routes in namespace %q, expected %d, got %d", tt.name, tt.routeNamespace,
				tt.expectedNumOfRoutesInNamespace, len(ia.routesToServicesMap[tt.routeNamespace]))
			require.Len(t, ia.routesToServicesMap[tt.routeNamespace][tt.routeName], tt.expectedNumOfRouteServices,
				"test %q, mismatch in number of services selected by route %q, expected %d, got %d", tt.name,
				types.NamespacedName{Name: tt.routeName, Namespace: tt.routeNamespace},
				tt.expectedNumOfRouteServices, len(ia.routesToServicesMap[tt.routeNamespace][tt.routeName]))
		})
	}
}

// helping struct to store ingress connection data to a specific peer in a directory
type peerAndIngressConns struct {
	peerName       string
	peerNamespace  string
	peerType       string
	allConnections bool
	ports          []int64
	protocol       string
}

// helping func - check if actual ingress connections to a single peer is as expected
func checkConnsEquality(t *testing.T, testName string, ingressConns map[string]*PeerAndIngressConnSet,
	expectedIngressToPeer *peerAndIngressConns) {
	peerStr := types.NamespacedName{Name: expectedIngressToPeer.peerName, Namespace: expectedIngressToPeer.peerNamespace}.String() +
		"[" + expectedIngressToPeer.peerType + "]"
	require.Contains(t, ingressConns, peerStr, "test: %q, expected to get ingress connections to peer %q but did not.", testName, peerStr)
	ingressConnsToPeer := ingressConns[peerStr]
	require.Equal(t, ingressConnsToPeer.ConnSet.AllConnections(), expectedIngressToPeer.allConnections,
		"test: %q, mismatch in ingress connections to %q", testName, peerStr)
	// if all connections is false; check if actual conns are as expected
	if !expectedIngressToPeer.allConnections {
		require.Contains(t, ingressConnsToPeer.ConnSet.ProtocolsAndPortsMap(), v1.Protocol(expectedIngressToPeer.protocol),
			"test: %q, mismatch in ingress connections to peer %q, should contain protocol %q", testName, peerStr, expectedIngressToPeer.protocol)
		connPortRange := ingressConnsToPeer.ConnSet.ProtocolsAndPortsMap()[v1.Protocol(expectedIngressToPeer.protocol)]
		require.Len(t, connPortRange, len(expectedIngressToPeer.ports),
			"test: %q, mismatch in ingress connections to %q", testName, peerStr)
		for i := range expectedIngressToPeer.ports {
			require.Equal(t, connPortRange[i].Start(), expectedIngressToPeer.ports[i],
				"test: %q, ingress connections to peer %q, should not contain port %d", testName, peerStr, connPortRange[i].Start())
		}
	}
}

func TestIngressAnalyzerConnectivityToPodsInDir(t *testing.T) {
	t.Parallel()
	cases := []struct {
		dirName             string // used also as the test name
		processingErrorsNum int
		ingressToPeers      []*peerAndIngressConns
	}{
		{
			dirName:             "acs_security_frontend_demos",
			processingErrorsNum: 0,
			ingressToPeers: []*peerAndIngressConns{
				{
					peerName:       "asset-cache",
					peerNamespace:  "frontend",
					peerType:       parser.Deployment,
					allConnections: false,
					ports:          []int64{8080},
					protocol:       "TCP",
				},
				{
					peerName:       "webapp",
					peerNamespace:  "frontend",
					peerType:       parser.Deployment,
					allConnections: false,
					ports:          []int64{8080},
					protocol:       "TCP",
				},
			},
		},
		{
			dirName:             "route_example_with_target_port",
			processingErrorsNum: 1, // no network-policies
			ingressToPeers: []*peerAndIngressConns{
				{
					peerName:       "workload-with-multiple-ports",
					peerNamespace:  "routes-world",
					peerType:       parser.Deployment,
					allConnections: false,
					ports:          []int64{8000, 8090},
					protocol:       "TCP",
				},
			},
		},
		{
			dirName:             "k8s_ingress_test",
			processingErrorsNum: 1, // no network-policies
			ingressToPeers: []*peerAndIngressConns{
				{
					peerName:       "details-v1-79f774bdb9",
					peerNamespace:  "default",
					peerType:       parser.ReplicaSet,
					allConnections: false,
					ports:          []int64{9080},
					protocol:       "TCP",
				},
			},
		},
		{
			dirName:             "demo_app_with_routes_and_ingress",
			processingErrorsNum: 1, // no network-policies
			ingressToPeers: []*peerAndIngressConns{
				{
					peerName:       "hello-world", // this workload is selected by both Ingress and Route objects
					peerNamespace:  "helloworld",
					peerType:       parser.Deployment,
					allConnections: false,
					ports:          []int64{8000},
					protocol:       "TCP",
				},
				{
					peerName:       "ingress-world", // this workload is selected by Ingress object only
					peerNamespace:  "ingressworld",
					peerType:       parser.Deployment,
					allConnections: false,
					ports:          []int64{8090},
					protocol:       "TCP",
				},
				{
					peerName:       "route-world", // this workload is selected by route object only
					peerNamespace:  "routeworld",
					peerType:       parser.Deployment,
					allConnections: false,
					ports:          []int64{8060},
					protocol:       "TCP",
				},
			},
		},
		{
			dirName:             "one_ingress_multiple_ports",
			processingErrorsNum: 1, // no network-policies
			ingressToPeers: []*peerAndIngressConns{
				{
					peerName:       "ingress-world-multiple-ports",
					peerNamespace:  "ingressworld",
					peerType:       parser.Deployment,
					allConnections: false,
					ports:          []int64{8000, 8090},
					protocol:       "TCP",
				},
			},
		},
		{
			dirName:             "one_ingress_multiple_services",
			processingErrorsNum: 1, // no network-policies
			ingressToPeers: []*peerAndIngressConns{
				{
					peerName:       "ingress-world-multiple-ports",
					peerNamespace:  "ingressworld",
					peerType:       parser.Deployment,
					allConnections: false,
					ports:          []int64{8000, 8090},
					protocol:       "TCP",
				},
			},
		},
		{
			dirName:             "multiple_ingress_objects_with_different_ports",
			processingErrorsNum: 1, // no network-policies
			ingressToPeers: []*peerAndIngressConns{
				{
					peerName:       "ingress-world-multiple-ports",
					peerNamespace:  "ingressworld",
					peerType:       parser.Deployment,
					allConnections: false,
					ports:          []int64{8050, 8090},
					protocol:       "TCP",
				},
			},
		},
		{
			dirName:             "ingress_example_with_named_port",
			processingErrorsNum: 1, // no network-policies
			ingressToPeers: []*peerAndIngressConns{
				{
					peerName:       "hello-deployment",
					peerNamespace:  "hello",
					peerType:       parser.Deployment,
					allConnections: false,
					ports:          []int64{8080},
					protocol:       "TCP",
				},
			},
		},
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.dirName, func(t *testing.T) {
			t.Parallel()
			ia := getIngressAnalyzerFromDirObjects(t, tt.dirName, tt.dirName, tt.processingErrorsNum)
			ingressConns, err := ia.AllowedIngressConnections()
			require.Empty(t, err, "test: %q", tt.dirName)
			for _, peerEntry := range tt.ingressToPeers {
				checkConnsEquality(t, tt.dirName, ingressConns, peerEntry)
			}
		})
	}
}
