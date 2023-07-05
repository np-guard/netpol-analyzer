package ingressanalyzer

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
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
	if len(processingErrs) > 0 {
		t.Fatalf("TestIngressAnalyzerWithRoutes errors: %v", processingErrs)
	}
	ia, err := NewIngressAnalyzerWithObjects(objects)
	if err != nil {
		t.Fatalf("TestIngressAnalyzerWithRoutes error: %v", err)
	}
	// routes map includes 1 namespace
	if len(ia.routesMap) != 1 {
		t.Fatalf("TestIngressAnalyzerWithRoutes: unexpected routesMap len: %d ", len(ia.routesMap))
	}
	// the routes namespace includes 2 different routes
	if len(ia.routesMap[routesNamespace]) != 2 {
		t.Fatalf("TestIngressAnalyzerWithRoutes: unexpected routes len: %d for namespace : %s ", len(ia.routesMap), routesNamespace)
	}
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
	if len(processingErrs) > 0 {
		t.Fatalf("TestIngressAnalyzerConnectivityToAPod errors: %v", processingErrs)
	}
	pe, err := eval.NewPolicyEngineWithObjects(objects)
	if err != nil {
		t.Fatalf("TestIngressAnalyzerConnectivityToAPod error: %v", err)
	}
	ia, err := NewIngressAnalyzerWithObjects(objects)
	if err != nil {
		t.Fatalf("TestIngressAnalyzerConnectivityToAPod error: %v", err)
	}
	peers, err := pe.GetPeersList()
	if err != nil {
		t.Fatalf("TestIngressAnalyzerConnectivityToAPod error: %v", err)
	}
	for _, entry := range testingEntries {
		for _, peer := range peers {
			if peer.Name() == entry.podName && peer.Namespace() == entry.podNamespace {
				conn, err := ia.AllowedIngressConnectionsToAWorkloadPeer(peer, pe)
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
