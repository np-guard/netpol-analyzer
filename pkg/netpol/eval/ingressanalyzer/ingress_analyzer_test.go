package ingressanalyzer

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"

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
	assert.Empty(t, processingErrs)
	ia, err := NewIngressAnalyzerWithObjects(objects)
	assert.Empty(t, err)
	// routes map includes 1 namespace
	assert.Len(t, ia.routesMap, 1)
	// the routes namespace includes 2 different routes
	assert.Len(t, ia.routesMap[routesNamespace], 2)
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
	assert.Empty(t, processingErrs)
	ia, err := NewIngressAnalyzerWithObjects(objects)
	assert.Empty(t, err)
	peers, err := ia.pe.GetPeersList()
	assert.Empty(t, err)
	for _, entry := range testingEntries {
		for _, peer := range peers {
			if peer.Name() == entry.podName && peer.Namespace() == entry.podNamespace {
				conn, err := ia.AllowedIngressConnectionsToAWorkloadPeer(peer)
				if err != nil {
					t.Fatalf("TestIngressAnalyzerConnectivityToAPod error: %v", err)
				}
				assert.Equal(t, conn.AllConnections(), entry.allConnections)
				if !conn.AllConnections() {
					assert.Contains(t, conn.ProtocolsAndPortsMap(), v1.Protocol(entry.protocol))
					connPortRange := conn.ProtocolsAndPortsMap()[v1.Protocol(entry.protocol)]
					assert.Equal(t, connPortRange[0].Start(), entry.port)
				}
			}
		}
	}
}
