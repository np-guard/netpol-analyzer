package ingressanalyzer

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/testutils"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/logger"
)

type serviceMapping struct {
	serviceName      string
	serviceNamespace string
	numPods          int
	expectedError    error
}

func TestServiceMappingToPods(t *testing.T) {
	// existing services to be tested
	serviceMappingList := []serviceMapping{
		{
			serviceName:      "demo",
			serviceNamespace: "default",
			numPods:          1,
			expectedError:    nil,
		},
		{
			serviceName:      "ingress-nginx-controller",
			serviceNamespace: "ingress-nginx",
			numPods:          1,
			expectedError:    nil,
		},
		{
			serviceName:      "ingress-nginx-controller-admission",
			serviceNamespace: "ingress-nginx",
			numPods:          2,
			expectedError:    nil,
		},
		{
			serviceName:      "kube-dns",
			serviceNamespace: "kube-system",
			numPods:          1,
			expectedError:    nil,
		},
		{
			serviceName:      "no-pods-selected",
			serviceNamespace: "default",
			numPods:          0,
			expectedError:    nil,
		},
		{
			serviceName:      "not-existing-svc",
			serviceNamespace: "default",
			numPods:          0,
			expectedError:    errors.New("service does not exist: default/not-existing-svc"),
		},
		{
			serviceName:      "not-existing-svc",
			serviceNamespace: "not-existing-ns",
			numPods:          0,
			expectedError:    errors.New("service does not exist: not-existing-ns/not-existing-svc"),
		},
	}

	path := filepath.Join(testutils.GetTestsDir(), "services", "services_with_selectors")
	objects, processingErrs := scanner.FilesToObjectsList(path)
	require.Len(t, processingErrs, 1) // no policies
	require.Len(t, objects, 16)       // found 5 services and 11 pods
	pe, err := eval.NewPolicyEngineWithObjects(objects)
	require.Empty(t, err)
	ia, err := NewIngressAnalyzerWithObjects(objects, pe, logger.NewDefaultLogger())
	require.Empty(t, err)

	for _, serviceMappingItem := range serviceMappingList {
		require.Len(t, ia.servicesToPeersMap[serviceMappingItem.serviceNamespace][serviceMappingItem.serviceName], serviceMappingItem.numPods)
	}
}

func TestNotSupportedService(t *testing.T) {
	path := filepath.Join(testutils.GetTestsDir(), "services", "services_without_selector")
	objects, processingErrs := scanner.FilesToObjectsList(path)
	require.Len(t, objects, 1)        // 1 service object
	require.Len(t, processingErrs, 2) // no policies nor workloads
	ia, err := NewIngressAnalyzerWithObjects(objects, nil, logger.NewDefaultLogger())
	require.Empty(t, err)
	require.Len(t, ia.servicesToPeersMap, 0) // service was ignored
}
