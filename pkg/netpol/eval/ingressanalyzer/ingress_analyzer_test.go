package ingressanalyzer

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/testutils"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/logger"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/scan"
)

// global scanner object for testing
var scanner = scan.NewResourcesScanner(logger.NewDefaultLogger(), false, filepath.WalkDir)

func TestIngressAnalyzerWithRoutes(t *testing.T) {
	routesNamespace := "frontend"
	path := filepath.Join(testutils.GetTestsDirFromInternalSubDir(), "acs_security_frontend_demos")
	objects, processingErrs := scanner.FilesToObjectsList(path)
	require.Empty(t, processingErrs)
	ia, err := NewIngressAnalyzerWithObjects(objects, nil)
	require.Empty(t, err)
	// routes map includes 1 namespace
	require.Len(t, ia.routesMap, 1)
	// the routes namespace includes 2 different routes
	require.Len(t, ia.routesMap[routesNamespace], 2)
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
	path := filepath.Join(testutils.GetTestsDirFromInternalSubDir(), "acs_security_frontend_demos")
	objects, processingErrs := scanner.FilesToObjectsList(path)
	require.Empty(t, processingErrs)
	pe, err := eval.NewPolicyEngineWithObjects(objects)
	require.Empty(t, err)
	ia, err := NewIngressAnalyzerWithObjects(objects, pe)
	require.Empty(t, err)
	ingressConns := ia.AllowedIngressConnections()
	peers, err := pe.GetPeersList()
	require.Empty(t, err)
	for _, entry := range testingEntries {
		for _, peer := range peers {
			if peer.Namespace() != entry.podNamespace {
				continue
			}
			if peer.Name() != entry.podName {
				continue
			}
			podPeer, err := pe.ConvertWorkloadPeerToPodPeer(peer)
			require.Empty(t, err)
			conn := ingressConns[podPeer.Pod]
			require.Equal(t, conn.AllConnections(), entry.allConnections)
			if !conn.AllConnections() {
				require.Contains(t, conn.ProtocolsAndPortsMap(), v1.Protocol(entry.protocol))
				connPortRange := conn.ProtocolsAndPortsMap()[v1.Protocol(entry.protocol)]
				require.Equal(t, connPortRange[0].Start(), entry.port)
			}
		}
	}
}
