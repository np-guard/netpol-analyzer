/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connlist

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes/fake"

	policyapifake "sigs.k8s.io/network-policy-api/pkg/client/clientset/versioned/fake"

	"github.com/np-guard/netpol-analyzer/pkg/internal/testutils"
	"github.com/np-guard/netpol-analyzer/pkg/logger"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/fsscanner"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/parser"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	apisv1a "sigs.k8s.io/network-policy-api/apis/v1alpha1"

	ocroutev1 "github.com/openshift/api/route/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestConnlistOnMockK8sServer(t *testing.T) {
	t.Parallel()
	for _, tt := range goodPathTests {
		if !tt.supportedOnLiveCluster {
			continue
		}
		t.Run(tt.testDirName, func(t *testing.T) {
			t.Parallel()
			for _, format := range tt.outputFormats {
				testutils.SkipRunningSVGTestOnGithub(t, format)
				pTest := prepareTest(tt.testDirName, tt.focusWorkloads, tt.focusWorkloadPeers, tt.focusDirection, tt.focusConn,
					format, tt.exposureAnalysis)
				runTest(t, pTest)
			}
		})
	}
}

func TestConnlistWithExplanationOnMockK8sServer(t *testing.T) {
	t.Parallel()
	for _, tt := range explainTests {
		if !tt.supportedOnLiveCluster {
			continue
		}
		t.Run(tt.testDirName, func(t *testing.T) {
			t.Parallel()
			pTest := prepareExplainTest(tt.testDirName, tt.focusWorkloads, tt.focusWorkloadPeers, tt.focusDirection, tt.focusConn,
				tt.explainOnly, tt.exposure)
			runTest(t, pTest)
		})
	}
}

func runTest(t *testing.T, pTest preparedTest) {
	infos, _ := fsscanner.GetResourceInfosFromDirPath([]string{pTest.dirPath}, true, false)
	objects, _ := parser.ResourceInfoListToK8sObjectsList(infos, logger.NewDefaultLogger(), true)

	k8sClientset, policyAPIClientset, err := buildFakeClientsets(objects)
	require.Nil(t, err, pTest.testInfo)

	// run connlist API funcs for connectivity analysis on live cluster
	res, _, err := pTest.analyzer.ConnlistFromK8sClusterWithPolicyAPI(k8sClientset, policyAPIClientset)
	require.Nil(t, err, pTest.testInfo)
	out, err := pTest.analyzer.ConnectionsListToString(res)
	require.Nil(t, err, pTest.testInfo)
	testutils.CheckActualVsExpectedOutputMatch(t, pTest.expectedOutputFileName, out,
		pTest.testInfo, currentPkg)
}

func buildFakeClientsets(objects []parser.K8sObject) (k8sClientset *fake.Clientset, policyAPIClientset *policyapifake.Clientset,
	err error) {
	// register a custom runtime scheme
	sch := runtime.NewScheme()
	err = registerScheme(sch)
	if err != nil {
		return nil, nil, err
	}
	// build simple fake clientset(s)
	k8sClientset = fake.NewSimpleClientset()
	policyAPIClientset = policyapifake.NewSimpleClientset()
	// add objects to the clientset(s)
	addObjectsByKindToClientsets(k8sClientset, policyAPIClientset, objects)
	return k8sClientset, policyAPIClientset, nil
}

//nolint:errcheck // all objects are valid
func addObjectsByKindToClientsets(k8sClientset *fake.Clientset, policyAPIClientset *policyapifake.Clientset,
	objects []parser.K8sObject) {
	for i := range objects {
		obj := objects[i]
		switch obj.Kind {
		case parser.Namespace:
			k8sClientset.CoreV1().Namespaces().Create(context.TODO(), obj.Namespace, metav1.CreateOptions{})
		case parser.NetworkPolicy:
			k8sClientset.NetworkingV1().NetworkPolicies(obj.NetworkPolicy.Namespace).Create(context.TODO(), obj.NetworkPolicy,
				metav1.CreateOptions{})
		case parser.AdminNetworkPolicy:
			policyAPIClientset.PolicyV1alpha1().AdminNetworkPolicies().Create(context.TODO(), obj.AdminNetworkPolicy,
				metav1.CreateOptions{})
		case parser.BaselineAdminNetworkPolicy:
			policyAPIClientset.PolicyV1alpha1().BaselineAdminNetworkPolicies().Create(context.TODO(), obj.BaselineAdminNetworkPolicy,
				metav1.CreateOptions{})
		case parser.Pod:
			k8sClientset.CoreV1().Pods(obj.Pod.Namespace).Create(context.TODO(), obj.Pod, metav1.CreateOptions{})
		// todo: if `ConnlistFromK8sClusterWithPolicyAPI` is changed to support following objects kinds, then uncomment those lines
		// case parser.ReplicaSet:
		// 	k8sClientset.AppsV1().ReplicaSets(obj.ReplicaSet.Namespace).Create(context.TODO(), obj.ReplicaSet, metav1.CreateOptions{})
		// case parser.ReplicationController:
		// 	k8sClientset.CoreV1().ReplicationControllers(obj.ReplicationController.Namespace).Create(context.TODO(),
		// 		obj.ReplicationController, metav1.CreateOptions{})
		// case parser.Deployment:
		// 	k8sClientset.AppsV1().Deployments(obj.Deployment.Namespace).Create(context.TODO(), obj.Deployment, metav1.CreateOptions{})
		// case parser.StatefulSet:
		// 	k8sClientset.AppsV1().StatefulSets(obj.StatefulSet.Namespace).Create(context.TODO(), obj.StatefulSet, metav1.CreateOptions{})
		// case parser.DaemonSet:
		// 	k8sClientset.AppsV1().DaemonSets(obj.DaemonSet.Namespace).Create(context.TODO(), obj.DaemonSet, metav1.CreateOptions{})
		// case parser.Job:
		// 	k8sClientset.BatchV1().Jobs(obj.Job.Namespace).Create(context.TODO(), obj.Job, metav1.CreateOptions{})
		// case parser.CronJob:
		// 	k8sClientset.BatchV1().CronJobs(obj.CronJob.Namespace).Create(context.TODO(), obj.CronJob, metav1.CreateOptions{})
		// case parser.Service:
		// 	k8sClientset.CoreV1().Services(obj.Service.Namespace).Create(context.TODO(), obj.Service, metav1.CreateOptions{})
		// case parser.Route:
		// case parser.Ingress:
		default:
			continue
		}
	}
}

// registerScheme registers needed API types, so we can create after then a fake clientset with parsed objects
func registerScheme(sch *runtime.Scheme) error {
	err := appsv1.AddToScheme(sch)
	if err != nil {
		return err
	}
	err = batchv1.AddToScheme(sch)
	if err != nil {
		return err
	}
	err = v1.AddToScheme(sch)
	if err != nil {
		return err
	}
	err = netv1.AddToScheme(sch)
	if err != nil {
		return err
	}
	err = apisv1a.AddToScheme(sch)
	if err != nil {
		return err
	}
	err = ocroutev1.AddToScheme(sch)
	if err != nil {
		return err
	}
	return metav1.AddMetaToScheme(sch)
}
