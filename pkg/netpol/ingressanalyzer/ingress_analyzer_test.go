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
	podName        string
	podNamespace   string
	allConnections bool
	port           int64
	protocol       string
}

func TestIngressAnalyzerConnectivityToAPod(t *testing.T) {
	testingEntries := []ingressToPod{
		{
			podName:        "asset-cache",
			podNamespace:   "frontend",
			allConnections: false,
			port:           8080,
			protocol:       "TCP",
		},
		{
			podName:        "webapp",
			podNamespace:   "frontend",
			allConnections: false,
			port:           8080,
			protocol:       "TCP",
		},
	}
	path := filepath.Join(testutils.GetTestsDir(), "acs_security_frontend_demos")
	objects, processingErrs := scanner.FilesToObjectsList(path)
	require.Empty(t, processingErrs)
	pe, err := eval.NewPolicyEngineWithObjects(objects)
	require.Empty(t, err)
	ia, err := NewIngressAnalyzerWithObjects(objects, pe, logger.NewDefaultLogger())
	require.Empty(t, err)
	ingressConns := ia.AllowedIngressConnections()
	require.Empty(t, err)
	for _, entry := range testingEntries {
		peerStr := types.NamespacedName{Name: entry.podName, Namespace: entry.podNamespace}.String()
		require.Contains(t, ingressConns, peerStr)
		conn := ingressConns[peerStr]
		require.Equal(t, conn.AllConnections(), entry.allConnections)
		if !conn.AllConnections() {
			require.Contains(t, conn.ProtocolsAndPortsMap(), v1.Protocol(entry.protocol))
			connPortRange := conn.ProtocolsAndPortsMap()[v1.Protocol(entry.protocol)]
			require.Equal(t, connPortRange[0].Start(), entry.port)
		}
	}
}
