/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0

*/

package testutils

import (
	"fmt"
	"strings"

	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/network-policy-api/apis/v1alpha1"

	"github.com/np-guard/netpol-analyzer/pkg/internal/output"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/parser"
)

// /////////////////////////////////////// ParsedResourcesTests ////////////////////////////////////

func init() {
	initParsedResourcesTestList(ANPConnectivityFromParsedResourcesTest)
	initParsedResourcesTestList(BANPConnectivityFromParsedResourcesTest)
	initParsedResourcesTestList(ANPWithNetPolV1FromParsedResourcesTest)
	initParsedResourcesTestList(BANPWithNetPolV1FromParsedResourcesTest)
	initParsedResourcesTestList(ANPWithBANPFromParsedResourcesTest)
}

var (
	udp        = v1.ProtocolUDP
	serve80tcp = "serve-80-tcp"
)

func newDefaultPod(namespace, name string, ports []int, protocols []v1.Protocol) v1.Pod {
	podObj := v1.Pod{}
	podObj.TypeMeta.APIVersion = "v1"
	podObj.TypeMeta.Kind = "Pod"
	podObj.ObjectMeta.Name = name
	podObj.ObjectMeta.Namespace = namespace
	podObj.Labels = map[string]string{"pod": name}
	for _, port := range ports {
		for _, protocol := range protocols {
			podObj.Spec.Containers = append(podObj.Spec.Containers, newDefaultContainer(port, protocol))
		}
	}
	return podObj
}

func newDefaultContainer(port int, protocol v1.Protocol) v1.Container {
	contObj := v1.Container{}
	contObj.Name = fmt.Sprintf("cont-%d-%s", port, strings.ToLower(string(protocol)))
	contObj.Ports = make([]v1.ContainerPort, 1)
	contObj.Ports[0].Name = fmt.Sprintf("serve-%d-%s", port, strings.ToLower(string(protocol)))
	contObj.Ports[0].ContainerPort = int32(port)
	contObj.Ports[0].Protocol = protocol
	return contObj
}

// The following struct holds information for pod creation for tests;
// the pods will be created for every namespace and every pod name below (the Cartesian product),
// having all ports/protocols below in their containers specs
type PodInfo struct {
	Namespaces []string
	PodNames   []string
	Ports      []int
	Protocols  []v1.Protocol
}

type EvalAllAllowedTest struct {
	Src       string
	Dst       string
	ExpResult string
}

// The following struct holds all test data needed for running a test
// and for verifying its results
type ParsedResourcesTest struct {
	Name                   string
	OutputFormat           string
	ExpectedOutputFileName string
	PodResources           PodInfo
	EvalTests              []EvalAllAllowedTest
	AnpList                []*v1alpha1.AdminNetworkPolicy
	Banp                   *v1alpha1.BaselineAdminNetworkPolicy
	NpList                 []*netv1.NetworkPolicy
	TestInfo               string
	Resources              []parser.K8sObject
}

func addMetaData(meta *metav1.ObjectMeta, cnt *int) {
	if meta.Name == "" {
		meta.Name = fmt.Sprintf("generated_name_%q", *cnt)
		*cnt++
	}
	if meta.Namespace == "" {
		meta.Namespace = "default"
	}
}

func initParsedResourcesTestList(testList []ParsedResourcesTest) {
	for i := 0; i < len(testList); i++ {
		test := &testList[i]
		test.initParsedResourcesTest()
	}
}

func (test *ParsedResourcesTest) initParsedResourcesTest() {
	var genCnt = 0
	test.TestInfo = fmt.Sprintf("test: %q, output format: %q", test.Name, test.OutputFormat)
	for _, ns := range test.PodResources.Namespaces {
		parsedNs := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, Labels: map[string]string{"ns": ns}}}
		k8sObj := parser.CreateNamespaceK8sObject(parsedNs)
		test.Resources = append(test.Resources, k8sObj)
		for _, pod := range test.PodResources.PodNames {
			parsedPod := newDefaultPod(ns, pod, test.PodResources.Ports, test.PodResources.Protocols)
			k8sObj := parser.CreatePodK8sObject(&parsedPod)
			test.Resources = append(test.Resources, k8sObj)
		}
	}
	for _, np := range test.NpList {
		addMetaData(&np.ObjectMeta, &genCnt)
		k8sObj := parser.CreateNetwordPolicyK8sObject(np)
		test.Resources = append(test.Resources, k8sObj)
	}
	for _, anp := range test.AnpList {
		addMetaData(&anp.ObjectMeta, &genCnt)
		k8sObj := parser.CreateAdminNetwordPolicyK8sObject(anp)
		test.Resources = append(test.Resources, k8sObj)
	}
	// Tanya: uncomment the code below when BaselineAdminNetworkPolicy is implemented
	// if test.Banp != nil {
	//  addMetaData(&test.Banp.ObjectMeta, &gen_cnt)
	// 	k8sObj := parser.CreateBaselineAdminNetwordPolicyK8sObject(test.Banp)
	// 	test.Resources = append(test.Resources, k8sObj)
	// }
}

//////////////////////////////////// The following tests are taken from /////////////////////////////////////
// https://github.com/kubernetes-sigs/network-policy-api/blob/main/cmd/policy-assistant/test/integration/integration_test.go

var (
	podInfo1 = PodInfo{Namespaces: []string{"x", "y"}, PodNames: []string{"a", "b"},
		Ports: []int{80, 81}, Protocols: []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP}}
	podInfo2 = PodInfo{Namespaces: []string{"x", "y"}, PodNames: []string{"a", "b"},
		Ports: []int{80}, Protocols: []v1.Protocol{v1.ProtocolTCP}}
	pods1 = &v1alpha1.NamespacedPod{
		NamespaceSelector: metav1.LabelSelector{
			MatchLabels: map[string]string{"ns": "x"},
		},
		PodSelector: metav1.LabelSelector{
			MatchLabels: map[string]string{"pod": "a"},
		},
	}
	pods2 = &v1alpha1.NamespacedPod{
		NamespaceSelector: metav1.LabelSelector{
			MatchLabels: map[string]string{"ns": "x"},
		},
		PodSelector: metav1.LabelSelector{
			MatchLabels: map[string]string{"pod": "b"},
		},
	}
	pods3 = &v1alpha1.NamespacedPod{
		NamespaceSelector: metav1.LabelSelector{
			MatchLabels: map[string]string{"ns": "y"},
		},
		PodSelector: metav1.LabelSelector{
			MatchLabels: map[string]string{"pod": "a"},
		},
	}
	pods4 = &v1alpha1.NamespacedPod{
		NamespaceSelector: metav1.LabelSelector{
			MatchLabels: map[string]string{"ns": "y"},
		},
		PodSelector: metav1.LabelSelector{
			MatchLabels: map[string]string{"pod": "b"},
		},
	}
	anpSubject = v1alpha1.AdminNetworkPolicySubject{
		Pods: pods1,
	}
	portsTCP8081 = &([]v1alpha1.AdminNetworkPolicyPort{
		{
			PortRange: &v1alpha1.PortRange{
				Protocol: v1.ProtocolTCP,
				Start:    80,
				End:      81,
			},
		},
	})
	portsTCPUDP8081 = &([]v1alpha1.AdminNetworkPolicyPort{
		{
			PortRange: &v1alpha1.PortRange{
				Protocol: v1.ProtocolTCP,
				Start:    80,
				End:      81,
			},
		},
		{
			PortRange: &v1alpha1.PortRange{
				Protocol: v1.ProtocolUDP,
				Start:    80,
				End:      81,
			},
		},
	})
	portsUDP80 = &([]v1alpha1.AdminNetworkPolicyPort{
		{
			PortNumber: &v1alpha1.Port{
				Port:     80,
				Protocol: v1.ProtocolUDP,
			},
		},
	})

	ANPConnectivityFromParsedResourcesTest = []ParsedResourcesTest{
		{
			Name:                   "egress port number protocol unspecified",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test1_anp_conn_from_parsed_res.txt",
			PodResources:           podInfo1,
			EvalTests: []EvalAllAllowedTest{
				{
					Src: "x/a", Dst: "x/b",
					ExpResult: "SCTP 1-65535,TCP 1-79,81-65535,UDP 1-65535",
				},
				{
					Src: "x/b", Dst: "x/a",
					ExpResult: "All Connections",
				},
			},
			AnpList: []*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 100,
						Subject:  anpSubject,
						Egress: []v1alpha1.AdminNetworkPolicyEgressRule{
							{
								Action: v1alpha1.AdminNetworkPolicyRuleActionDeny,
								To: []v1alpha1.AdminNetworkPolicyEgressPeer{
									{
										Pods: pods2,
									},
								},
								Ports: &([]v1alpha1.AdminNetworkPolicyPort{
									{
										PortNumber: &v1alpha1.Port{
											Port: 80,
										},
									},
								}),
							},
						},
					},
				},
			},
		},
		{
			Name:                   "ingress port number protocol unspecified",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test2_anp_conn_from_parsed_res.txt",
			PodResources:           podInfo1,
			EvalTests: []EvalAllAllowedTest{
				{
					Src: "x/b", Dst: "x/a",
					ExpResult: "SCTP 1-65535,TCP 1-79,81-65535,UDP 1-65535",
				},
				{
					Src: "x/b", Dst: "y/a",
					ExpResult: "All Connections",
				},
			},
			AnpList: []*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 100,
						Subject:  anpSubject,
						Ingress: []v1alpha1.AdminNetworkPolicyIngressRule{
							{
								Action: v1alpha1.AdminNetworkPolicyRuleActionDeny,
								From: []v1alpha1.AdminNetworkPolicyIngressPeer{
									{
										Pods: pods2,
									},
								},
								Ports: &([]v1alpha1.AdminNetworkPolicyPort{
									{
										PortNumber: &v1alpha1.Port{
											Port: 80,
										},
									},
								}),
							},
						},
					},
				},
			},
		},
		{
			Name:                   "ingress named port",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test3_anp_conn_from_parsed_res.txt",
			PodResources:           podInfo1,
			EvalTests: []EvalAllAllowedTest{
				{
					Src: "x/b", Dst: "x/a",
					ExpResult: "SCTP 1-65535,TCP 1-79,81-65535,UDP 1-65535",
				},
				{
					Src: "y/b", Dst: "x/a",
					ExpResult: "All Connections",
				},
			},
			AnpList: []*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 100,
						Subject:  anpSubject,
						Ingress: []v1alpha1.AdminNetworkPolicyIngressRule{
							{
								Action: v1alpha1.AdminNetworkPolicyRuleActionDeny,
								From: []v1alpha1.AdminNetworkPolicyIngressPeer{
									{
										Pods: pods2,
									},
								},
								Ports: &([]v1alpha1.AdminNetworkPolicyPort{
									{
										NamedPort: &serve80tcp,
									},
								}),
							},
						},
					},
				},
			},
		},
		{
			Name:                   "ingress same labels port range",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test4_anp_conn_from_parsed_res.txt",
			PodResources: PodInfo{Namespaces: []string{"x", "y", "z"}, PodNames: []string{"a", "b", "c"},
				Ports: []int{80, 81}, Protocols: []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP}},
			EvalTests: []EvalAllAllowedTest{
				{
					Src: "x/c", Dst: "x/a",
					ExpResult: "SCTP 1-65535,TCP 1-79,82-65535,UDP 1-65535",
				},
				{
					Src: "y/c", Dst: "z/b",
					ExpResult: "All Connections",
				},
			},
			AnpList: []*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 100,
						Subject:  anpSubject,
						Ingress: []v1alpha1.AdminNetworkPolicyIngressRule{
							{
								Action: v1alpha1.AdminNetworkPolicyRuleActionDeny,
								Ports:  portsTCP8081,
								From: []v1alpha1.AdminNetworkPolicyIngressPeer{
									{
										Pods: &v1alpha1.NamespacedPod{
											NamespaceSelector: metav1.LabelSelector{
												MatchLabels: map[string]string{"ns": "x"},
											},
											PodSelector: metav1.LabelSelector{},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			Name:                   "not same labels",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test5_anp_conn_from_parsed_res.txt",
			PodResources:           podInfo1,
			EvalTests: []EvalAllAllowedTest{
				{
					Src: "y/a", Dst: "x/a",
					ExpResult: "SCTP 1-65535,TCP 1-65535,UDP 1-79,81-65535",
				},
				{
					Src: "y/b", Dst: "y/a",
					ExpResult: "All Connections",
				},
			},
			AnpList: []*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 100,
						Subject:  anpSubject,
						Ingress: []v1alpha1.AdminNetworkPolicyIngressRule{
							{
								Action: v1alpha1.AdminNetworkPolicyRuleActionDeny,
								From: []v1alpha1.AdminNetworkPolicyIngressPeer{
									{
										Pods: &v1alpha1.NamespacedPod{
											NamespaceSelector: metav1.LabelSelector{
												MatchLabels: map[string]string{"ns": "y"},
											},
											PodSelector: metav1.LabelSelector{},
										},
									},
								},
								Ports: portsUDP80,
							},
						},
					},
				},
			},
		},
		{
			Name:                   "ordering matters for overlapping rules (order #1)",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test6_anp_conn_from_parsed_res.txt",
			PodResources:           podInfo1,
			EvalTests: []EvalAllAllowedTest{
				{
					Src: "y/b", Dst: "x/a",
					ExpResult: "SCTP 1-65535,TCP 1-65535,UDP 1-79,81-65535",
				},
				{
					Src: "y/b", Dst: "y/a",
					ExpResult: "All Connections",
				},
			},
			AnpList: []*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 100,
						Subject:  anpSubject,
						Ingress: []v1alpha1.AdminNetworkPolicyIngressRule{
							{
								Action: v1alpha1.AdminNetworkPolicyRuleActionAllow,
								From: []v1alpha1.AdminNetworkPolicyIngressPeer{
									{
										Pods: pods3,
									},
								},
								Ports: portsUDP80,
							},
							{
								Action: v1alpha1.AdminNetworkPolicyRuleActionDeny,
								From: []v1alpha1.AdminNetworkPolicyIngressPeer{
									{
										Pods: &v1alpha1.NamespacedPod{
											NamespaceSelector: metav1.LabelSelector{
												MatchLabels: map[string]string{"ns": "y"},
											},
											PodSelector: metav1.LabelSelector{},
										},
									},
								},
								Ports: portsUDP80,
							},
						},
					},
				},
			},
		},
		{
			Name:                   "ordering matters for overlapping rules (order #2)",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test7_anp_conn_from_parsed_res.txt",
			PodResources:           podInfo1,
			EvalTests: []EvalAllAllowedTest{
				{
					Src: "y/a", Dst: "x/a",
					ExpResult: "SCTP 1-65535,TCP 1-65535,UDP 1-79,81-65535",
				},
				{
					Src: "y/b", Dst: "y/a",
					ExpResult: "All Connections",
				},
			},
			AnpList: []*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 100,
						Subject:  anpSubject,
						Ingress: []v1alpha1.AdminNetworkPolicyIngressRule{
							{
								Action: v1alpha1.AdminNetworkPolicyRuleActionDeny,
								From: []v1alpha1.AdminNetworkPolicyIngressPeer{
									{
										Pods: &v1alpha1.NamespacedPod{
											NamespaceSelector: metav1.LabelSelector{
												MatchLabels: map[string]string{"ns": "y"},
											},
											PodSelector: metav1.LabelSelector{},
										},
									},
								},
								Ports: portsUDP80,
							},
							{
								Action: v1alpha1.AdminNetworkPolicyRuleActionAllow,
								From: []v1alpha1.AdminNetworkPolicyIngressPeer{
									{
										Pods: pods3,
									},
								},
								Ports: portsUDP80,
							},
						},
					},
				},
			},
		},
		{
			Name:                   "deny all egress",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test8_anp_conn_from_parsed_res.txt",
			PodResources:           podInfo1,
			EvalTests: []EvalAllAllowedTest{
				{
					Src: "x/b", Dst: "y/a",
					ExpResult: "SCTP 1-65535,TCP 1-79,82-65535,UDP 1-79,82-65535",
				},
				{
					Src: "0.0.0.0/0", Dst: "y/a",
					ExpResult: "All Connections",
				},
			},
			AnpList: []*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 100,
						Subject: v1alpha1.AdminNetworkPolicySubject{
							Namespaces: &metav1.LabelSelector{},
						},
						Egress: []v1alpha1.AdminNetworkPolicyEgressRule{
							{
								Action: v1alpha1.AdminNetworkPolicyRuleActionDeny,
								To: []v1alpha1.AdminNetworkPolicyEgressPeer{
									{
										Namespaces: &metav1.LabelSelector{},
									},
								},
								Ports: portsTCPUDP8081,
							},
						},
					},
				},
			},
		},
		{
			Name:                   "multiple ANPs (priority order #1)",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test9_anp_conn_from_parsed_res.txt",
			PodResources:           podInfo1,
			EvalTests: []EvalAllAllowedTest{
				{
					Src: "x/a", Dst: "y/b",
					ExpResult: "All Connections",
				},
				{
					Src: "0.0.0.0/0", Dst: "y/a",
					ExpResult: "All Connections",
				},
			},
			AnpList: []*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 99,
						Subject: v1alpha1.AdminNetworkPolicySubject{
							Namespaces: &metav1.LabelSelector{},
						},
						Egress: []v1alpha1.AdminNetworkPolicyEgressRule{
							{
								Action: v1alpha1.AdminNetworkPolicyRuleActionAllow,
								To: []v1alpha1.AdminNetworkPolicyEgressPeer{
									{
										Namespaces: &metav1.LabelSelector{},
									},
								},
								Ports: portsTCPUDP8081,
							},
						},
					},
				},
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 100,
						Subject: v1alpha1.AdminNetworkPolicySubject{
							Namespaces: &metav1.LabelSelector{},
						},
						Egress: []v1alpha1.AdminNetworkPolicyEgressRule{
							{
								Action: v1alpha1.AdminNetworkPolicyRuleActionDeny,
								To: []v1alpha1.AdminNetworkPolicyEgressPeer{
									{
										Namespaces: &metav1.LabelSelector{},
									},
								},
								Ports: portsTCPUDP8081,
							},
						},
					},
				},
			},
		},
		{
			Name:                   "multiple ANPs (priority order #2)",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test10_anp_conn_from_parsed_res.txt",
			PodResources:           podInfo1,
			EvalTests: []EvalAllAllowedTest{
				{
					Src: "x/a", Dst: "y/b",
					ExpResult: "SCTP 1-65535,TCP 1-79,82-65535,UDP 1-79,82-65535",
				},
				{
					Src: "0.0.0.0/0", Dst: "y/a",
					ExpResult: "All Connections",
				},
			},
			AnpList: []*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 101,
						Subject: v1alpha1.AdminNetworkPolicySubject{
							Namespaces: &metav1.LabelSelector{},
						},
						Egress: []v1alpha1.AdminNetworkPolicyEgressRule{
							{
								Action: v1alpha1.AdminNetworkPolicyRuleActionAllow,
								To: []v1alpha1.AdminNetworkPolicyEgressPeer{
									{
										Namespaces: &metav1.LabelSelector{},
									},
								},
								Ports: portsTCPUDP8081,
							},
						},
					},
				},
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 100,
						Subject: v1alpha1.AdminNetworkPolicySubject{
							Namespaces: &metav1.LabelSelector{},
						},
						Egress: []v1alpha1.AdminNetworkPolicyEgressRule{
							{
								Action: v1alpha1.AdminNetworkPolicyRuleActionDeny,
								To: []v1alpha1.AdminNetworkPolicyEgressPeer{
									{
										Namespaces: &metav1.LabelSelector{},
									},
								},
								Ports: portsTCPUDP8081,
							},
						},
					},
				},
			},
		},
	}

	BANPConnectivityFromParsedResourcesTest = []ParsedResourcesTest{
		{
			Name:                   "egress",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test1_banp_conn_from_parsed_res.txt",
			PodResources:           podInfo1,
			// Tanya: build eval tests whenever BaselineAdminNetworkPolicy is implemented
			EvalTests: []EvalAllAllowedTest{
				{
					Src: "x/a", Dst: "y/b",
					ExpResult: "",
				},
				{
					Src: "0.0.0.0/0", Dst: "y/a",
					ExpResult: "",
				},
			},
			Banp: &v1alpha1.BaselineAdminNetworkPolicy{
				Spec: v1alpha1.BaselineAdminNetworkPolicySpec{
					Subject: anpSubject,
					Egress: []v1alpha1.BaselineAdminNetworkPolicyEgressRule{
						{
							Action: v1alpha1.BaselineAdminNetworkPolicyRuleActionDeny,
							To: []v1alpha1.AdminNetworkPolicyEgressPeer{
								{
									Pods: &v1alpha1.NamespacedPod{
										NamespaceSelector: metav1.LabelSelector{},
										PodSelector: metav1.LabelSelector{
											MatchLabels: map[string]string{"pod": "b"},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			Name:                   "ingress",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test2_banp_conn_from_parsed_res.txt",
			PodResources:           podInfo1,
			// Tanya: build eval tests whenever BaselineAdminNetworkPolicy is implemented
			EvalTests: []EvalAllAllowedTest{
				{
					Src: "x/a", Dst: "y/b",
					ExpResult: "",
				},
				{
					Src: "0.0.0.0/0", Dst: "y/a",
					ExpResult: "",
				},
			},
			Banp: &v1alpha1.BaselineAdminNetworkPolicy{
				Spec: v1alpha1.BaselineAdminNetworkPolicySpec{
					Subject: anpSubject,
					Ingress: []v1alpha1.BaselineAdminNetworkPolicyIngressRule{
						{
							Action: v1alpha1.BaselineAdminNetworkPolicyRuleActionDeny,
							From: []v1alpha1.AdminNetworkPolicyIngressPeer{
								{
									Pods: &v1alpha1.NamespacedPod{
										NamespaceSelector: metav1.LabelSelector{},
										PodSelector: metav1.LabelSelector{
											MatchLabels: map[string]string{"pod": "b"},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			Name:                   "ordering matters for overlapping rules (order #1)",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test3_banp_conn_from_parsed_res.txt",
			PodResources:           podInfo2,
			// Tanya: build eval tests whenever BaselineAdminNetworkPolicy is implemented
			EvalTests: []EvalAllAllowedTest{
				{
					Src: "x/a", Dst: "y/b",
					ExpResult: "",
				},
				{
					Src: "0.0.0.0/0", Dst: "y/a",
					ExpResult: "",
				},
			},
			Banp: &v1alpha1.BaselineAdminNetworkPolicy{
				Spec: v1alpha1.BaselineAdminNetworkPolicySpec{
					Subject: v1alpha1.AdminNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{},
					},
					Ingress: []v1alpha1.BaselineAdminNetworkPolicyIngressRule{
						{
							Action: v1alpha1.BaselineAdminNetworkPolicyRuleActionAllow,
							From: []v1alpha1.AdminNetworkPolicyIngressPeer{
								{
									Pods: pods3,
								},
							},
						},
						{
							Action: v1alpha1.BaselineAdminNetworkPolicyRuleActionDeny,
							From: []v1alpha1.AdminNetworkPolicyIngressPeer{
								{
									Namespaces: &metav1.LabelSelector{},
								},
							},
						},
					},
				},
			},
		},
		{
			Name:                   "ordering matters for overlapping rules (order #2)",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test4_banp_conn_from_parsed_res.txt",
			PodResources:           podInfo2,
			// Tanya: build eval tests whenever BaselineAdminNetworkPolicy is implemented
			EvalTests: []EvalAllAllowedTest{
				{
					Src: "x/a", Dst: "y/b",
					ExpResult: "",
				},
				{
					Src: "0.0.0.0/0", Dst: "y/a",
					ExpResult: "",
				},
			},
			Banp: &v1alpha1.BaselineAdminNetworkPolicy{
				Spec: v1alpha1.BaselineAdminNetworkPolicySpec{
					Subject: v1alpha1.AdminNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{},
					},
					Ingress: []v1alpha1.BaselineAdminNetworkPolicyIngressRule{
						{
							Action: v1alpha1.BaselineAdminNetworkPolicyRuleActionDeny,
							From: []v1alpha1.AdminNetworkPolicyIngressPeer{
								{
									Namespaces: &metav1.LabelSelector{},
								},
							},
						},
						{
							Action: v1alpha1.BaselineAdminNetworkPolicyRuleActionDeny,
							From: []v1alpha1.AdminNetworkPolicyIngressPeer{
								{
									Pods: pods4,
								},
							},
						},
					},
				},
			},
		},
	}

	ANPWithNetPolV1FromParsedResourcesTest = []ParsedResourcesTest{
		{
			Name:                   "ANP allow all over NetPol",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test1_anp_npv1_conn_from_parsed_res.txt",
			PodResources:           podInfo1,
			EvalTests: []EvalAllAllowedTest{
				{
					Src: "x/b", Dst: "x/a",
					ExpResult: "TCP 80-81,UDP 80-81",
				},
				{
					Src: "x/b", Dst: "y/a",
					ExpResult: "All Connections",
				},
			},
			NpList: []*netv1.NetworkPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "x",
						Name:      "base",
					},
					Spec: netv1.NetworkPolicySpec{
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{"pod": "a"},
						},
						Ingress: []netv1.NetworkPolicyIngressRule{
							{
								Ports: []netv1.NetworkPolicyPort{
									{
										Protocol: &udp,
										Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 80},
									},
								},
							},
						},
						PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
					},
				},
			},
			AnpList: []*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 99,
						Subject: v1alpha1.AdminNetworkPolicySubject{
							Namespaces: &metav1.LabelSelector{},
						},
						Ingress: []v1alpha1.AdminNetworkPolicyIngressRule{
							{
								Action: v1alpha1.AdminNetworkPolicyRuleActionAllow,
								From: []v1alpha1.AdminNetworkPolicyIngressPeer{
									{
										Namespaces: &metav1.LabelSelector{},
									},
								},
								Ports: portsTCPUDP8081,
							},
						},
					},
				},
			},
		},
		{
			Name:                   "ANP allow some over NetPol",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test2_anp_npv1_conn_from_parsed_res.txt",
			PodResources:           podInfo1,
			EvalTests: []EvalAllAllowedTest{
				{
					Src: "x/b", Dst: "x/a",
					ExpResult: "TCP 80-81,UDP 80-81",
				},
				{
					Src: "x/b", Dst: "y/a",
					ExpResult: "All Connections",
				},
			},
			NpList: []*netv1.NetworkPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "x",
						Name:      "base",
					},
					Spec: netv1.NetworkPolicySpec{
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{"pod": "a"},
						},
						Ingress: []netv1.NetworkPolicyIngressRule{
							{
								Ports: []netv1.NetworkPolicyPort{
									{
										Protocol: &udp,
										Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 80},
									},
								},
							},
						},
						PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
					},
				},
			},
			AnpList: []*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 99,
						Subject: v1alpha1.AdminNetworkPolicySubject{
							Namespaces: &metav1.LabelSelector{},
						},
						Ingress: []v1alpha1.AdminNetworkPolicyIngressRule{
							{
								Action: v1alpha1.AdminNetworkPolicyRuleActionAllow,
								From: []v1alpha1.AdminNetworkPolicyIngressPeer{
									{
										Namespaces: &metav1.LabelSelector{
											MatchLabels: map[string]string{"ns": "x"},
										},
									},
								},
								Ports: portsTCPUDP8081,
							},
						},
					},
				},
			},
		},
	}

	BANPWithNetPolV1FromParsedResourcesTest = []ParsedResourcesTest{
		{
			Name:                   "BANP deny all after NetPol",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test1_banp_npv1_conn_from_parsed_res.txt",
			PodResources: PodInfo{Namespaces: []string{"x"}, PodNames: []string{"a", "b"},
				Ports: []int{80, 81}, Protocols: []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP}},
			// Tanya: build eval tests whenever BaselineAdminNetworkPolicy is implemented
			EvalTests: []EvalAllAllowedTest{
				{
					Src: "x/a", Dst: "y/b",
					ExpResult: "",
				},
				{
					Src: "0.0.0.0/0", Dst: "y/a",
					ExpResult: "",
				},
			},
			NpList: []*netv1.NetworkPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "x",
						Name:      "base",
					},
					Spec: netv1.NetworkPolicySpec{
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{"pod": "a"},
						},
						Ingress: []netv1.NetworkPolicyIngressRule{
							{
								From: []netv1.NetworkPolicyPeer{
									{
										PodSelector: &metav1.LabelSelector{
											MatchLabels: map[string]string{"pod": "b"},
										},
									},
								},
								Ports: []netv1.NetworkPolicyPort{
									{
										Protocol: &udp,
										Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 80},
									},
								},
							},
						},
						PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
					},
				},
			},
			Banp: &v1alpha1.BaselineAdminNetworkPolicy{
				Spec: v1alpha1.BaselineAdminNetworkPolicySpec{
					Subject: v1alpha1.AdminNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{},
					},
					Ingress: []v1alpha1.BaselineAdminNetworkPolicyIngressRule{
						{
							Action: v1alpha1.BaselineAdminNetworkPolicyRuleActionDeny,
							From: []v1alpha1.AdminNetworkPolicyIngressPeer{
								{
									Namespaces: &metav1.LabelSelector{},
								},
							},
						},
					},
				},
			},
		},
	}

	ANPWithBANPFromParsedResourcesTest = []ParsedResourcesTest{
		{
			Name:                   "BANP deny all after ANP",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test1_anp_banp_from_parsed_res.txt",
			PodResources:           podInfo1,
			// Tanya: build eval tests whenever BaselineAdminNetworkPolicy is implemented
			EvalTests: []EvalAllAllowedTest{
				{
					Src: "x/a", Dst: "y/b",
					ExpResult: "",
				},
				{
					Src: "0.0.0.0/0", Dst: "y/a",
					ExpResult: "",
				},
			},
			AnpList: []*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 100,
						Subject:  anpSubject,
						Ingress: []v1alpha1.AdminNetworkPolicyIngressRule{
							{
								Action: v1alpha1.AdminNetworkPolicyRuleActionAllow,
								From: []v1alpha1.AdminNetworkPolicyIngressPeer{
									{
										Namespaces: &metav1.LabelSelector{
											MatchLabels: map[string]string{"ns": "x"},
										},
									},
								},
								Ports: portsUDP80,
							},
						},
					},
				},
			},
			Banp: &v1alpha1.BaselineAdminNetworkPolicy{
				Spec: v1alpha1.BaselineAdminNetworkPolicySpec{
					Subject: v1alpha1.AdminNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{},
					},
					Ingress: []v1alpha1.BaselineAdminNetworkPolicyIngressRule{
						{
							Action: v1alpha1.BaselineAdminNetworkPolicyRuleActionDeny,
							From: []v1alpha1.AdminNetworkPolicyIngressPeer{
								{
									Namespaces: &metav1.LabelSelector{},
								},
							},
						},
					},
				},
			},
		},
		{
			Name:                   "ANP pass some and allow rest over BANP",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test2_anp_banp_from_parsed_res.txt",
			PodResources:           podInfo1,
			// Tanya: build eval tests whenever BaselineAdminNetworkPolicy is implemented
			EvalTests: []EvalAllAllowedTest{
				{
					Src: "x/a", Dst: "y/b",
					ExpResult: "",
				},
				{
					Src: "0.0.0.0/0", Dst: "y/a",
					ExpResult: "",
				},
			},
			AnpList: []*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 100,
						Subject:  anpSubject,
						Ingress: []v1alpha1.AdminNetworkPolicyIngressRule{
							{
								Action: v1alpha1.AdminNetworkPolicyRuleActionPass,
								From: []v1alpha1.AdminNetworkPolicyIngressPeer{
									{
										Namespaces: &metav1.LabelSelector{
											MatchLabels: map[string]string{"ns": "x"},
										},
									},
								},
								Ports: portsUDP80,
							},
						},
					},
				},
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 101,
						Subject: v1alpha1.AdminNetworkPolicySubject{
							Namespaces: &metav1.LabelSelector{},
						},
						Ingress: []v1alpha1.AdminNetworkPolicyIngressRule{
							{
								Action: v1alpha1.AdminNetworkPolicyRuleActionAllow,
								From: []v1alpha1.AdminNetworkPolicyIngressPeer{
									{
										Namespaces: &metav1.LabelSelector{},
									},
								},
							},
						},
					},
				},
			},
			Banp: &v1alpha1.BaselineAdminNetworkPolicy{
				Spec: v1alpha1.BaselineAdminNetworkPolicySpec{
					Subject: v1alpha1.AdminNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{},
					},
					Ingress: []v1alpha1.BaselineAdminNetworkPolicyIngressRule{
						{
							Action: v1alpha1.BaselineAdminNetworkPolicyRuleActionDeny,
							From: []v1alpha1.AdminNetworkPolicyIngressPeer{
								{
									Namespaces: &metav1.LabelSelector{},
								},
							},
						},
					},
				},
			},
		},
	}
)
