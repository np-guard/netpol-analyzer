/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ingressanalyzer

import (
	"testing"

	"k8s.io/apimachinery/pkg/types"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/netpol-analyzer/pkg/internal/testutils"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/fsscanner"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/parser"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
)

const servicesDirName = "services"

// TestServiceMappingToPods - tests the num of pods selected by a given service if any.
// not existed services or not supported services (e.g. services without selectors are ignored, thus no pods are selected)
func TestServiceMappingToPods(t *testing.T) {
	t.Parallel()
	servicesDir := testutils.GetTestDirPath(servicesDirName)
	cases := []struct {
		name                             string
		serviceName                      string
		serviceNamespace                 string
		numWorkloadsSelectedByTheService int
	}{
		{
			name:                             "default/demo_svc_in_services_dir_selects_1_pod",
			serviceName:                      "demo",
			serviceNamespace:                 "default",
			numWorkloadsSelectedByTheService: 1,
		},
		{
			name:                             "ingress-nginx/ingress-nginx-controller_svc_in_services_dir_selects_1_pod",
			serviceName:                      "ingress-nginx-controller",
			serviceNamespace:                 "ingress-nginx",
			numWorkloadsSelectedByTheService: 1,
		},
		{
			name:                             "ingress-nginx/ingress-nginx-controller-admission_svc_exists_and_selects_2_pods",
			serviceName:                      "ingress-nginx-controller-admission",
			serviceNamespace:                 "ingress-nginx",
			numWorkloadsSelectedByTheService: 2,
		},
		{
			name:                             "kube-system/kube-dns_service_exists_and_selects_1_pod",
			serviceName:                      "kube-dns",
			serviceNamespace:                 "kube-system",
			numWorkloadsSelectedByTheService: 1,
		},
		{
			name:                             "default/no-pods-selected_service_exists_and_selects_no_pods",
			serviceName:                      "no-pods-selected",
			serviceNamespace:                 "default",
			numWorkloadsSelectedByTheService: 0,
		},
		{
			name:                             "default/not-existing-svc_service_is_not_existing_should_be_ignored",
			serviceName:                      "not-existing-svc",
			serviceNamespace:                 "default",
			numWorkloadsSelectedByTheService: 0,
		},
		{
			name:                             "not-existing-ns/not-existing-svc_service_is_not_existing_should_be_ignored",
			serviceName:                      "not-existing-svc",
			serviceNamespace:                 "not-existing-ns",
			numWorkloadsSelectedByTheService: 0,
		},
		{
			name:                             "default/svc-without-selector_service_is_without_selectors_then_not_supported_should_be_ignored",
			serviceName:                      "svc-without-selector",
			serviceNamespace:                 "default",
			numWorkloadsSelectedByTheService: 0,
		},
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rList, _ := fsscanner.GetResourceInfosFromDirPath([]string{servicesDir}, true, false)
			objects, processingErrs := parser.ResourceInfoListToK8sObjectsList(rList, l, false)
			require.Len(t, processingErrs, 1, "test: %q", tt.name) // no policies
			require.Len(t, objects, 17, "test: %q", tt.name)       // found 6 services and 11 pods
			pe, err := eval.NewPolicyEngineWithObjects(objects)
			require.Empty(t, err, "test: %q", tt.name)
			ia, err := NewIngressAnalyzerWithObjects(objects, pe, l, false)
			require.Empty(t, err, "test: %q", tt.name)
			require.Len(t, ia.servicesToPortsAndPeersMap[tt.serviceNamespace][tt.serviceName].peers,
				tt.numWorkloadsSelectedByTheService, "mismatch for test %q, service %q expected to map %d pods, got %d",
				tt.name, types.NamespacedName{Name: tt.serviceName, Namespace: tt.serviceNamespace}, tt.numWorkloadsSelectedByTheService,
				ia.servicesToPortsAndPeersMap[tt.serviceNamespace][tt.serviceName].peers)
		})
	}
}
