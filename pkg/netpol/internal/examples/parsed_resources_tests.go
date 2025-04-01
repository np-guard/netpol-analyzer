/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0

*/

package examples

import (
	"fmt"
	"strings"

	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/network-policy-api/apis/v1alpha1"

	"github.com/np-guard/netpol-analyzer/pkg/manifests/parser"
)

// /////////////////////////////////////// ParsedResourcesTests ////////////////////////////////////
// this file contains pattern for adding tests from parsed resources for netpol packages (api tests)

var (
	genCnt = 0
)

func newDefaultPod(namespace, name string, ports []int32, protocols []v1.Protocol) *v1.Pod {
	podObj := v1.Pod{}
	podObj.APIVersion = "v1"
	podObj.Kind = podKind
	podObj.Name = name
	podObj.Namespace = namespace
	podObj.Status.HostIP = parser.IPv4LoopbackAddr
	podObj.Status.PodIPs = []v1.PodIP{{IP: parser.IPv4LoopbackAddr}}
	podObj.Labels = map[string]string{"pod": name}
	for _, port := range ports {
		for _, protocol := range protocols {
			podObj.Spec.Containers = append(podObj.Spec.Containers, newDefaultContainer(port, protocol))
		}
	}
	addMetaData(&podObj.ObjectMeta, true)
	return &podObj
}

func newDefaultContainer(port int32, protocol v1.Protocol) v1.Container {
	contObj := v1.Container{}
	contObj.Name = fmt.Sprintf("cont-%d-%s", port, strings.ToLower(string(protocol)))
	contObj.Ports = make([]v1.ContainerPort, 1)
	contObj.Ports[0].Name = fmt.Sprintf("serve-%d-%s", port, strings.ToLower(string(protocol)))
	contObj.Ports[0].ContainerPort = port
	contObj.Ports[0].Protocol = protocol
	return contObj
}

// The following struct holds information for pod creation for tests;
// the pods will be created for every namespace and every pod name below (the Cartesian product),
// having all ports/protocols below in their containers specs
type podInfo struct {
	namespaces []string
	podNames   []string
	ports      []int32
	protocols  []v1.Protocol
}

type resources struct {
	nsList  []*v1.Namespace
	podList []*v1.Pod
}

type EvalAllowedConnTest struct {
	Src       string
	Dst       string
	ExpResult string
}

// The following struct holds all test data needed for running a test from parsed resources
// and for verifying its results
type ParsedResourcesTest struct {
	Name                   string
	OutputFormat           string
	ExpectedOutputFileName string
	EvalTests              []EvalAllowedConnTest
	Resources              *resources
	AnpList                []*v1alpha1.AdminNetworkPolicy
	Banp                   *v1alpha1.BaselineAdminNetworkPolicy
	NpList                 []*netv1.NetworkPolicy
	TestInfo               string
}

func addMetaData(meta *metav1.ObjectMeta, addNsName bool) {
	if meta.Name == "" {
		meta.Name = fmt.Sprintf("generated_name_%q", genCnt)
		genCnt++
	}
	if addNsName && meta.Namespace == "" {
		meta.Namespace = metav1.NamespaceDefault
	}
}

func initResources(podInfo *podInfo) *resources {
	res := &resources{[]*v1.Namespace{}, []*v1.Pod{}}
	for _, ns := range podInfo.namespaces {
		res.nsList = append(res.nsList, &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, Labels: map[string]string{"ns": ns}}})
		for _, pod := range podInfo.podNames {
			res.podList = append(res.podList, newDefaultPod(ns, pod, podInfo.ports, podInfo.protocols))
		}
	}
	return res
}

func initNpList(npList []*netv1.NetworkPolicy) []*netv1.NetworkPolicy {
	for _, np := range npList {
		addMetaData(&np.ObjectMeta, true)
	}
	return npList
}

func initAnpList(anpList []*v1alpha1.AdminNetworkPolicy) []*v1alpha1.AdminNetworkPolicy {
	for _, anp := range anpList {
		// ANPs are cluster scoped (has no namespace name)
		addMetaData(&anp.ObjectMeta, false)
	}
	return anpList
}

func initBanp(banp *v1alpha1.BaselineAdminNetworkPolicy) *v1alpha1.BaselineAdminNetworkPolicy {
	banp.Name = "default" // "must use default as the name when creating a BaselineAdminNetworkPolicy object."
	return banp
}

func (test *ParsedResourcesTest) GetK8sObjects() []parser.K8sObject {
	res := []parser.K8sObject{}
	test.TestInfo = fmt.Sprintf("test: %q, output format: %q", test.Name, test.OutputFormat)
	for _, ns := range test.Resources.nsList {
		res = append(res, createNamespaceK8sObject(ns))
	}
	for _, pod := range test.Resources.podList {
		res = append(res, createPodK8sObject(pod))
	}
	for _, np := range test.NpList {
		res = append(res, createNetworkPolicyK8sObject(np))
	}
	for _, anp := range test.AnpList {
		res = append(res, createAdminNetworkPolicyK8sObject(anp))
	}
	if test.Banp != nil {
		res = append(res, createBaselineAdminNetworkPolicyK8sObject(test.Banp))
	}
	return res
}

func createPodK8sObject(pod *v1.Pod) parser.K8sObject {
	k8sObj := parser.K8sObject{}
	k8sObj.Kind = podKind
	k8sObj.Pod = pod
	return k8sObj
}

func createNamespaceK8sObject(ns *v1.Namespace) parser.K8sObject {
	k8sObj := parser.K8sObject{}
	k8sObj.Kind = "Namespace"
	k8sObj.Namespace = ns
	return k8sObj
}

func createNetworkPolicyK8sObject(np *netv1.NetworkPolicy) parser.K8sObject {
	k8sObj := parser.K8sObject{}
	k8sObj.Kind = "NetworkPolicy"
	k8sObj.NetworkPolicy = np
	return k8sObj
}

func createAdminNetworkPolicyK8sObject(anp *v1alpha1.AdminNetworkPolicy) parser.K8sObject {
	k8sObj := parser.K8sObject{}
	k8sObj.Kind = "AdminNetworkPolicy"
	k8sObj.AdminNetworkPolicy = anp
	return k8sObj
}

func createBaselineAdminNetworkPolicyK8sObject(banp *v1alpha1.BaselineAdminNetworkPolicy) parser.K8sObject {
	k8sObj := parser.K8sObject{}
	k8sObj.Kind = "BaselineAdminNetworkPolicy"
	k8sObj.BaselineAdminNetworkPolicy = banp
	return k8sObj
}
