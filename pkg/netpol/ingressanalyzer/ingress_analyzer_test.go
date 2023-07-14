package ingressanalyzer

import (
	"path/filepath"
	"testing"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/testutils"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/logger"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/scan"
)

// global scanner object for testing
var scanner = scan.NewResourcesScanner(logger.NewDefaultLogger(), false, filepath.WalkDir)

func TestIngressAnalyzerWithRoutes(t *testing.T) {
	routesNamespace := "frontend"
	routeNameExample := "webapp"
	path := filepath.Join(testutils.GetTestsDir(), "acs_security_frontend_demos")
	objects, processingErrs := scanner.FilesToObjectsList(path)
	require.Empty(t, processingErrs)
	pe, err := eval.NewPolicyEngineWithObjects(objects)
	require.Empty(t, err)
	ia, err := NewIngressAnalyzerWithObjects(objects, pe, logger.NewDefaultLogger())
	require.Empty(t, err)
	// routes map includes 1 namespace
	require.Len(t, ia.routesToServicesMap, 1)
	// the routes namespace includes 2 different routes
	require.Len(t, ia.routesToServicesMap[routesNamespace], 2)
	// each route is mapped to 1 service - check 1 for example
	require.Len(t, ia.routesToServicesMap[routesNamespace][routeNameExample], 1)
}

type ingressToPod struct {
	peerName       string
	peerNamespace  string
	peerType       string
	allConnections bool
	ports          []int64
	protocol       string
}

type testEntry struct {
	dirpath            string
	processingErrs     int
	testIngressEntries []ingressToPod
}

func TestIngressAnalyzerConnectivityToAPod(t *testing.T) {
	testingEntries := []testEntry{
		{
			dirpath:        "acs_security_frontend_demos",
			processingErrs: 0,
			testIngressEntries: []ingressToPod{
				{
					peerName:       "asset-cache",
					peerNamespace:  "frontend",
					peerType:       scan.Deployment,
					allConnections: false,
					ports:          []int64{8080},
					protocol:       "TCP",
				},
				{
					peerName:       "webapp",
					peerNamespace:  "frontend",
					peerType:       scan.Deployment,
					allConnections: false,
					ports:          []int64{8080},
					protocol:       "TCP",
				},
			},
		},
		{
			dirpath:        "k8s_ingress_test",
			processingErrs: 1, // no network-policies
			testIngressEntries: []ingressToPod{
				{
					peerName:       "details-v1-79f774bdb9",
					peerNamespace:  "default",
					peerType:       scan.ReplicaSet,
					allConnections: false,
					ports:          []int64{9080},
					protocol:       "TCP",
				},
			},
		},
		{
			dirpath:        "demo_app_with_routes_and_ingress",
			processingErrs: 1, // no network-policies
			testIngressEntries: []ingressToPod{
				{
					peerName:       "hello-world", // this workload is selected by both Ingress and Route objects
					peerNamespace:  "helloworld",
					peerType:       scan.Deployment,
					allConnections: false,
					ports:          []int64{8000},
					protocol:       "TCP",
				},
				{
					peerName:       "ingress-world", // this workload is selected by Ingress object only
					peerNamespace:  "ingressworld",
					peerType:       scan.Deployment,
					allConnections: false,
					ports:          []int64{8090},
					protocol:       "TCP",
				},
				{
					peerName:       "route-world", // this workload is selected by route object only
					peerNamespace:  "routeworld",
					peerType:       scan.Deployment,
					allConnections: false,
					ports:          []int64{8060},
					protocol:       "TCP",
				},
			},
		},
		{
			dirpath:        "one_ingress_multiple_ports",
			processingErrs: 1, // no network-policies
			testIngressEntries: []ingressToPod{
				{
					peerName:       "ingress-world-multiple-ports",
					peerNamespace:  "ingressworld",
					peerType:       scan.Deployment,
					allConnections: false,
					ports:          []int64{8000, 8090},
					protocol:       "TCP",
				},
			},
		},
		{
			dirpath:        "multiple_ingress_objects_with_different_ports",
			processingErrs: 1, // no network-policies
			testIngressEntries: []ingressToPod{
				{
					peerName:       "ingress-world-multiple-ports",
					peerNamespace:  "ingressworld",
					peerType:       scan.Deployment,
					allConnections: false,
					ports:          []int64{8050, 8090},
					protocol:       "TCP",
				},
			},
		},
	}

	for _, testEntry := range testingEntries {
		path := filepath.Join(testutils.GetTestsDir(), testEntry.dirpath)
		objects, processingErrs := scanner.FilesToObjectsList(path)
		require.Len(t, processingErrs, testEntry.processingErrs)
		pe, err := eval.NewPolicyEngineWithObjects(objects)
		require.Empty(t, err)
		ia, err := NewIngressAnalyzerWithObjects(objects, pe, logger.NewDefaultLogger())
		require.Empty(t, err)
		ingressConns := ia.AllowedIngressConnections()
		require.Empty(t, err)
		for _, ingressEentry := range testEntry.testIngressEntries {
			peerStr := types.NamespacedName{Name: ingressEentry.peerName, Namespace: ingressEentry.peerNamespace}.String() +
				"[" + ingressEentry.peerType + "]"
			require.Contains(t, ingressConns, peerStr)
			conn := ingressConns[peerStr]
			require.Equal(t, conn.AllConnections(), ingressEentry.allConnections)
			if !conn.AllConnections() {
				require.Contains(t, conn.ProtocolsAndPortsMap(), v1.Protocol(ingressEentry.protocol))
				connPortRange := conn.ProtocolsAndPortsMap()[v1.Protocol(ingressEentry.protocol)]
				require.Len(t, connPortRange, len(ingressEentry.ports))
				for i := range ingressEentry.ports {
					require.Equal(t, connPortRange[i].Start(), ingressEentry.ports[i])
				}
			}
		}
	}
}
