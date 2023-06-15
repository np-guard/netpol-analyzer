package eval

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/testutils"
)

type serviceMapping struct {
	serviceName      string
	serviceNamespace string
	numPods          int
}

func TestServiceMappingToPods(t *testing.T) {
	// existing services to be tested
	serviceMappingList := []serviceMapping{
		{
			serviceName:      "demo",
			serviceNamespace: "default",
			numPods:          1,
		},
		{
			serviceName:      "ingress-nginx-controller",
			serviceNamespace: "ingress-nginx",
			numPods:          1,
		},
		{
			serviceName:      "ingress-nginx-controller-admission",
			serviceNamespace: "ingress-nginx",
			numPods:          2,
		},
		{
			serviceName:      "kube-dns",
			serviceNamespace: "kube-system",
			numPods:          1,
		},
	}

	path := filepath.Join(testutils.GetTestsDir(), "services", "services_with_selectors")
	objects, processingErrs := scanner.FilesToObjectsList(path)
	require.Len(t, processingErrs, 1) // no policies
	require.Len(t, objects, 15)       // found 4 services and 11 pods
	pe, err := NewPolicyEngineWithObjects(objects)
	require.Empty(t, err)

	for _, serviceMappingItem := range serviceMappingList {
		pods, err := pe.getServicePods(serviceMappingItem.serviceName, serviceMappingItem.serviceNamespace)
		require.Empty(t, err)
		require.Len(t, pods, serviceMappingItem.numPods)
	}
}

func TestNotSupportedService(t *testing.T) {
	path := filepath.Join(testutils.GetTestsDir(), "services", "services_without_selector")
	objects, processingErrs := scanner.FilesToObjectsList(path)
	require.Len(t, objects, 1)
	require.Len(t, processingErrs, 2) // no policies nor workloads
	_, err := NewPolicyEngineWithObjects(objects)
	require.Equal(t, err.Error(), "K8s Service without selectors is not supported")
}
