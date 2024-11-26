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
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/network-policy-api/apis/v1alpha1"

	"github.com/np-guard/netpol-analyzer/pkg/internal/output"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/parser"
)

//////////////////////////////////// The following tests are taken from or tested also with /////////////////////////////////////
// https://github.com/kubernetes-sigs/network-policy-api/blob/main/cmd/policy-assistant/test/integration/integration_test.go

const (
	podKind                = "Pod"
	allConnsStr            = "All Connections"
	allButTCP80            = "SCTP 1-65535,TCP 1-79,81-65535,UDP 1-65535"
	allButTCP80A81         = "SCTP 1-65535,TCP 1-79,82-65535,UDP 1-65535"
	connUDP80              = "UDP 80"
	allButUDP80            = "SCTP 1-65535,TCP 1-65535,UDP 1-79,81-65535"
	allButTCP80A81UDP80A81 = "SCTP 1-65535,TCP 1-79,82-65535,UDP 1-79,82-65535"
	allButTCP80UDP80       = "SCTP 1-65535,TCP 1-79,81-65535,UDP 1-79,81-65535"
	noConns                = "No Connections"
	connTCP80A81UDP80A81   = "TCP 80-81,UDP 80-81"
	connTCP80A81           = "TCP 80-81"
	priority100            = 100
)

// variables which are used by the anp examples below:
var (
	udp        = v1.ProtocolUDP
	serve80tcp = "serve-80-tcp"
	genCnt     = 0
)

func newDefaultPod(namespace, name string, ports []int32, protocols []v1.Protocol) *v1.Pod {
	podObj := v1.Pod{}
	podObj.TypeMeta.APIVersion = "v1"
	podObj.TypeMeta.Kind = podKind
	podObj.ObjectMeta.Name = name
	podObj.ObjectMeta.Namespace = namespace
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
type PodInfo struct {
	Namespaces []string
	PodNames   []string
	Ports      []int32
	Protocols  []v1.Protocol
}

type Resources struct {
	NsList  []*v1.Namespace
	PodList []*v1.Pod
}

type EvalAllowedConnTest struct {
	Src       string
	Dst       string
	ExpResult string
}

// The following struct holds all test data needed for running a test
// and for verifying its results
type ParsedResourcesTest struct {
	Name                   string
	OutputFormat           string
	Explain                bool
	ExpectedOutputFileName string
	EvalTests              []EvalAllowedConnTest
	Resources              *Resources
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

func initResources(podInfo *PodInfo) *Resources {
	res := &Resources{[]*v1.Namespace{}, []*v1.Pod{}}
	for _, ns := range podInfo.Namespaces {
		res.NsList = append(res.NsList, &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, Labels: map[string]string{"ns": ns}}})
		for _, pod := range podInfo.PodNames {
			res.PodList = append(res.PodList, newDefaultPod(ns, pod, podInfo.Ports, podInfo.Protocols))
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
	for _, ns := range test.Resources.NsList {
		res = append(res, createNamespaceK8sObject(ns))
	}
	for _, pod := range test.Resources.PodList {
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

//////////////////////////////////// The following tests are taken from /////////////////////////////////////
// https://github.com/kubernetes-sigs/network-policy-api/blob/main/cmd/policy-assistant/test/integration/integration_test.go

var (
	podInfo1 = &PodInfo{Namespaces: []string{"x", "y"}, PodNames: []string{"a", "b"},
		Ports: []int32{80, 81}, Protocols: []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP}}
	podInfo2 = &PodInfo{Namespaces: []string{"x", "y"}, PodNames: []string{"a", "b"},
		Ports: []int32{80}, Protocols: []v1.Protocol{v1.ProtocolTCP}}
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
	pods5 = &v1alpha1.NamespacedPod{
		NamespaceSelector: metav1.LabelSelector{},
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
	ports80 = &([]v1alpha1.AdminNetworkPolicyPort{
		{
			PortNumber: &v1alpha1.Port{
				Port: 80,
			},
		},
	})
	allNamespacesSubject = v1alpha1.AdminNetworkPolicySubject{
		Namespaces: &metav1.LabelSelector{},
	}
	subjectNsY = v1alpha1.AdminNetworkPolicySubject{
		Namespaces: &metav1.LabelSelector{
			MatchLabels: map[string]string{"ns": "y"},
		},
	}
	subjectNsX = v1alpha1.AdminNetworkPolicySubject{
		Namespaces: &metav1.LabelSelector{
			MatchLabels: map[string]string{"ns": "x"},
		},
	}
	toXPeer = []v1alpha1.AdminNetworkPolicyEgressPeer{
		{
			Namespaces: &metav1.LabelSelector{
				MatchLabels: map[string]string{"ns": "x"},
			},
		},
	}
	fromYPeer = []v1alpha1.AdminNetworkPolicyIngressPeer{
		{
			Namespaces: &metav1.LabelSelector{
				MatchLabels: map[string]string{"ns": "y"},
			},
		},
	}
	fromXPeer = []v1alpha1.AdminNetworkPolicyIngressPeer{
		{
			Namespaces: &metav1.LabelSelector{
				MatchLabels: map[string]string{"ns": "x"},
			},
		},
	}
	egressRuleDenyPorts80 = []v1alpha1.AdminNetworkPolicyEgressRule{
		{
			Action: v1alpha1.AdminNetworkPolicyRuleActionDeny,
			To: []v1alpha1.AdminNetworkPolicyEgressPeer{
				{
					Pods: pods2,
				},
			},
			Ports: ports80,
		},
	}
	egressRuleAllowPortsTCPUDP8081 = []v1alpha1.AdminNetworkPolicyEgressRule{
		{
			Action: v1alpha1.AdminNetworkPolicyRuleActionAllow,
			To: []v1alpha1.AdminNetworkPolicyEgressPeer{
				{
					Namespaces: &metav1.LabelSelector{},
				},
			},
			Ports: portsTCPUDP8081,
		},
	}
	egressRuleAllowToXTCP80 = v1alpha1.AdminNetworkPolicyEgressRule{
		Action: v1alpha1.AdminNetworkPolicyRuleActionAllow,
		To:     toXPeer,
		Ports:  ports80,
	}
	egressRuleAllowToXTCP8081 = v1alpha1.AdminNetworkPolicyEgressRule{
		Action: v1alpha1.AdminNetworkPolicyRuleActionAllow,
		To:     toXPeer,
		Ports:  portsTCP8081,
	}
	egressRuleDenyAllToX = v1alpha1.AdminNetworkPolicyEgressRule{
		Action: v1alpha1.AdminNetworkPolicyRuleActionDeny,
		To:     toXPeer,
	}
	egressRulesAllowToXOnlyTCP80 = []v1alpha1.AdminNetworkPolicyEgressRule{egressRuleAllowToXTCP80, egressRuleDenyAllToX}
	ingressRuleAllowFromYUDP80   = v1alpha1.AdminNetworkPolicyIngressRule{
		Action: v1alpha1.AdminNetworkPolicyRuleActionAllow,
		From:   fromYPeer,
		Ports:  portsUDP80,
	}
	ingressRuleAllowAllFromY = v1alpha1.AdminNetworkPolicyIngressRule{
		Action: v1alpha1.AdminNetworkPolicyRuleActionAllow,
		From:   fromYPeer,
	}
	ingressRuleDenyAllFromY = v1alpha1.AdminNetworkPolicyIngressRule{
		Action: v1alpha1.AdminNetworkPolicyRuleActionDeny,
		From:   fromYPeer,
	}
	ingressRulesAllowFromYOnlyUDP80 = []v1alpha1.AdminNetworkPolicyIngressRule{ingressRuleAllowFromYUDP80, ingressRuleDenyAllFromY}
	egressRulePassToXUDP80          = v1alpha1.AdminNetworkPolicyEgressRule{
		Action: v1alpha1.AdminNetworkPolicyRuleActionPass,
		To:     toXPeer,
		Ports:  portsUDP80,
	}
	egressRulePassToXTCP80 = v1alpha1.AdminNetworkPolicyEgressRule{
		Action: v1alpha1.AdminNetworkPolicyRuleActionPass,
		To:     toXPeer,
		Ports:  ports80,
	}
	egressRulePassAllToX = v1alpha1.AdminNetworkPolicyEgressRule{
		Action: v1alpha1.AdminNetworkPolicyRuleActionPass,
		To:     toXPeer,
	}
	egressRuleDenyToXUDP80 = v1alpha1.AdminNetworkPolicyEgressRule{
		Action: v1alpha1.AdminNetworkPolicyRuleActionDeny,
		To:     toXPeer,
		Ports:  portsUDP80,
	}
	egressRuleAllowToXUDP80 = v1alpha1.AdminNetworkPolicyEgressRule{
		Action: v1alpha1.AdminNetworkPolicyRuleActionAllow,
		To:     toXPeer,
		Ports:  portsUDP80,
	}
	egressRuleAllowAllToX = v1alpha1.AdminNetworkPolicyEgressRule{
		Action: v1alpha1.AdminNetworkPolicyRuleActionAllow,
		To:     toXPeer,
	}
	ingressRulePassFromYUDP80 = v1alpha1.AdminNetworkPolicyIngressRule{
		Action: v1alpha1.AdminNetworkPolicyRuleActionPass,
		From:   fromYPeer,
		Ports:  portsUDP80,
	}
	ingressRuleDenyFromYUDP80 = v1alpha1.AdminNetworkPolicyIngressRule{
		Action: v1alpha1.AdminNetworkPolicyRuleActionDeny,
		From:   fromYPeer,
		Ports:  portsUDP80,
	}
	ingressRuleAllowAllFromX = v1alpha1.AdminNetworkPolicyIngressRule{
		Action: v1alpha1.AdminNetworkPolicyRuleActionAllow,
		From:   fromXPeer,
	}
	anp1 = v1alpha1.AdminNetworkPolicySpec{
		Priority: priority100,
		Subject:  allNamespacesSubject,
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
	}
	banpDenyAllFromY = initBanp(&v1alpha1.BaselineAdminNetworkPolicy{
		Spec: v1alpha1.BaselineAdminNetworkPolicySpec{
			Subject: allNamespacesSubject,
			Ingress: []v1alpha1.BaselineAdminNetworkPolicyIngressRule{
				{
					Action: v1alpha1.BaselineAdminNetworkPolicyRuleActionDeny,
					From:   fromYPeer,
				},
			},
		},
	})
	banpAllowAllFromY = initBanp(&v1alpha1.BaselineAdminNetworkPolicy{
		Spec: v1alpha1.BaselineAdminNetworkPolicySpec{
			Subject: allNamespacesSubject,
			Ingress: []v1alpha1.BaselineAdminNetworkPolicyIngressRule{
				{
					Action: v1alpha1.BaselineAdminNetworkPolicyRuleActionAllow,
					From:   fromYPeer,
				},
			},
		},
	})
	banpDenyAllToX = initBanp(&v1alpha1.BaselineAdminNetworkPolicy{
		Spec: v1alpha1.BaselineAdminNetworkPolicySpec{
			Subject: subjectNsY,
			Egress: []v1alpha1.BaselineAdminNetworkPolicyEgressRule{
				{
					Action: v1alpha1.BaselineAdminNetworkPolicyRuleActionDeny,
					To:     toXPeer,
				},
			},
		},
	})
	banpAllowSpecificPort = initBanp(&v1alpha1.BaselineAdminNetworkPolicy{
		Spec: v1alpha1.BaselineAdminNetworkPolicySpec{
			Subject: v1alpha1.AdminNetworkPolicySubject{
				Pods: pods1,
			},
			Egress: []v1alpha1.BaselineAdminNetworkPolicyEgressRule{
				{
					Action: v1alpha1.BaselineAdminNetworkPolicyRuleActionAllow,
					To: []v1alpha1.AdminNetworkPolicyEgressPeer{
						{
							Pods: pods2,
						},
					},
					Ports: ports80,
				},
			},
		},
	})
	banpDenySpecificPort = initBanp(&v1alpha1.BaselineAdminNetworkPolicy{
		Spec: v1alpha1.BaselineAdminNetworkPolicySpec{
			Subject: v1alpha1.AdminNetworkPolicySubject{
				Pods: pods1,
			},
			Egress: []v1alpha1.BaselineAdminNetworkPolicyEgressRule{
				{
					Action: v1alpha1.BaselineAdminNetworkPolicyRuleActionDeny,
					To: []v1alpha1.AdminNetworkPolicyEgressPeer{
						{
							Pods: pods2,
						},
					},
					Ports: ports80,
				},
			},
		},
	})
	anpAllowSpecificPort = v1alpha1.AdminNetworkPolicySpec{
		Priority: priority100,
		Subject: v1alpha1.AdminNetworkPolicySubject{
			Pods: pods1,
		},
		Egress: []v1alpha1.AdminNetworkPolicyEgressRule{
			{
				Action: v1alpha1.AdminNetworkPolicyRuleActionAllow,
				To: []v1alpha1.AdminNetworkPolicyEgressPeer{
					{
						Pods: pods2,
					},
				},
				Ports: portsUDP80,
			},
		},
	}
	anpDenySpecificPort = v1alpha1.AdminNetworkPolicySpec{
		Priority: priority100,
		Subject: v1alpha1.AdminNetworkPolicySubject{
			Pods: pods1,
		},
		Egress: []v1alpha1.AdminNetworkPolicyEgressRule{
			{
				Action: v1alpha1.AdminNetworkPolicyRuleActionDeny,
				To: []v1alpha1.AdminNetworkPolicyEgressPeer{
					{
						Pods: pods2,
					},
				},
				Ports: portsUDP80,
			},
		},
	}
)

// testing examples for K8S Network Policy API
var (
	ANPConnectivityFromParsedResourcesTest = []ParsedResourcesTest{
		{
			Name:                   "egress port number protocol unspecified",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test1_anp_conn_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/a", Dst: "x/b",
					ExpResult: allButTCP80,
				},
				{
					Src: "x/b", Dst: "x/a",
					ExpResult: allConnsStr,
				},
			},
			Resources: initResources(podInfo1),
			AnpList: initAnpList([]*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: priority100,
						Subject:  anpSubject,
						Egress:   egressRuleDenyPorts80,
					},
				},
			}),
		},
		{
			Name:                   "ingress port number protocol unspecified",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test2_anp_conn_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/b", Dst: "x/a",
					ExpResult: allButTCP80,
				},
				{
					Src: "x/b", Dst: "y/a",
					ExpResult: allConnsStr,
				},
			},
			Resources: initResources(podInfo1),
			AnpList: initAnpList([]*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: priority100,
						Subject:  anpSubject,
						Ingress: []v1alpha1.AdminNetworkPolicyIngressRule{
							{
								Action: v1alpha1.AdminNetworkPolicyRuleActionDeny,
								From: []v1alpha1.AdminNetworkPolicyIngressPeer{
									{
										Pods: pods2,
									},
								},
								Ports: ports80,
							},
						},
					},
				},
			}),
		},
		{
			Name:                   "ingress named port",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test3_anp_conn_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/b", Dst: "x/a",
					ExpResult: allButTCP80,
				},
				{
					Src: "y/b", Dst: "x/a",
					ExpResult: allConnsStr,
				},
			},
			Resources: initResources(podInfo1),
			AnpList: initAnpList([]*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: priority100,
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
			}),
		},
		{
			Name:                   "ingress same labels port range",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test4_anp_conn_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/c", Dst: "x/a",
					ExpResult: allButTCP80A81,
				},
				{
					Src: "y/c", Dst: "z/b",
					ExpResult: allConnsStr,
				},
			},
			Resources: initResources(&PodInfo{Namespaces: []string{"x", "y", "z"}, PodNames: []string{"a", "b", "c"},
				Ports: []int32{80, 81}, Protocols: []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP}}),
			AnpList: initAnpList([]*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: priority100,
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
			}),
		},
		{
			Name:                   "not same labels",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test5_anp_conn_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "y/a", Dst: "x/a",
					ExpResult: allButUDP80,
				},
				{
					Src: "y/b", Dst: "y/a",
					ExpResult: allConnsStr,
				},
			},
			Resources: initResources(podInfo1),
			AnpList: initAnpList([]*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: priority100,
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
			}),
		},
		{
			Name:                   "ordering matters for overlapping rules (order #1)",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test6_anp_conn_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "y/b", Dst: "x/a",
					ExpResult: allButUDP80,
				},
				{
					Src: "y/b", Dst: "y/a",
					ExpResult: allConnsStr,
				},
			},
			Resources: initResources(podInfo1),
			AnpList: initAnpList([]*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: priority100,
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
			}),
		},
		{
			Name:                   "ordering matters for overlapping rules (order #2)",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test7_anp_conn_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "y/a", Dst: "x/a",
					ExpResult: allButUDP80,
				},
				{
					Src: "y/b", Dst: "y/a",
					ExpResult: allConnsStr,
				},
			},
			Resources: initResources(podInfo1),
			AnpList: initAnpList([]*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: priority100,
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
			}),
		},
		{
			Name:                   "deny all egress",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test8_anp_conn_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/b", Dst: "y/a",
					ExpResult: allButTCP80A81UDP80A81,
				},
				{
					Src: "0.0.0.0/0", Dst: "y/a",
					ExpResult: allConnsStr,
				},
			},
			Resources: initResources(podInfo1),
			AnpList: initAnpList([]*v1alpha1.AdminNetworkPolicy{
				{
					Spec: anp1,
				},
			}),
		},
		{
			Name:                   "multiple ANPs (priority order #1)",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test9_anp_conn_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/a", Dst: "y/b",
					ExpResult: allConnsStr,
				},
				{
					Src: "0.0.0.0/0", Dst: "y/a",
					ExpResult: allConnsStr,
				},
			},
			Resources: initResources(podInfo1),
			AnpList: initAnpList([]*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 99,
						Subject:  allNamespacesSubject,
						Egress:   egressRuleAllowPortsTCPUDP8081,
					},
				},
				{
					Spec: anp1,
				},
			}),
		},
		{
			Name:                   "multiple ANPs (priority order #2)",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test10_anp_conn_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/a", Dst: "y/b",
					ExpResult: allButTCP80A81UDP80A81,
				},
				{
					Src: "0.0.0.0/0", Dst: "x/a",
					ExpResult: allConnsStr,
				},
			},
			Resources: initResources(podInfo1),
			AnpList: initAnpList([]*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 101,
						Subject:  allNamespacesSubject,
						Egress:   egressRuleAllowPortsTCPUDP8081,
					},
				},
				{
					Spec: anp1,
				},
			}),
		},
		{
			Name: "ANP with unmatched ingress and egress connection #1",
			// ANP:
			// - subject is all namespaces (x,y)
			// - ingress rules: (from y : allow only udp 80)
			//    1.allow UDP80 from y
			//    2. deny all from y
			// - egress rules to x with (to x : allow only tcp 80)
			//    1. allow TCP 80 to x
			//    2. deny all to x
			//  (no intersection between allow ingress, egress)
			// what happens from y->x:
			// actual table form policy-assistant: ( y -> x is blocked)
			// +--------+---------+---------+---------+---------+
			// | TCP/80 |   X/A   |   X/B   |   Y/A   |   Y/B   |
			// | TCP/81 |         |         |         |         |
			// | UDP/80 |         |         |         |         |
			// | UDP/81 |         |         |         |         |
			// +--------+---------+---------+---------+---------+
			// | x/a    | # # # # | . X X X | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | x/b    | . X X X | # # # # | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | y/a    | X X X X | X X X X | # # # # | X X . X |
			// +--------+---------+---------+---------+---------+
			// | y/b    | X X X X | X X X X | X X . X | # # # # |
			// +--------+---------+---------+---------+---------+
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test1_anp_unmatched_ingress_egress_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/a", Dst: "y/b",
					ExpResult: allConnsStr,
				},
				{
					Src: "y/a", Dst: "x/b",
					ExpResult: noConns,
				},
			},
			Resources: initResources(podInfo1),
			AnpList: initAnpList([]*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: priority100,
						Subject:  allNamespacesSubject,
						Egress:   egressRulesAllowToXOnlyTCP80,
						Ingress:  ingressRulesAllowFromYOnlyUDP80,
					},
				},
			}),
		},
		{
			Name: "ANP with unmatched ingress and egress connection #2",
			// ANP:
			// - subject is all namespaces (x,y),
			// same as above without deny rules:
			// - ingress rule from y : allow UDP80
			// - egress rule to x : allow TCP 80
			// what happens from y->x:
			// actual table from policy-assistant: all allowed from y to x
			// +--------+---------+---------+---------+---------+
			// | TCP/80 |   X/A   |   X/B   |   Y/A   |   Y/B   |
			// | TCP/81 |         |         |         |         |
			// | UDP/80 |         |         |         |         |
			// | UDP/81 |         |         |         |         |
			// +--------+---------+---------+---------+---------+
			// | x/a    | # # # # | . . . . | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | x/b    | . . . . | # # # # | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | y/a    | . . . . | . . . . | # # # # | . . . . |
			// +--------+---------+---------+---------+---------+
			// | y/b    | . . . . | . . . . | . . . . | # # # # |
			// +--------+---------+---------+---------+---------+
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test2_anp_unmatched_ingress_egress_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/a", Dst: "y/b",
					ExpResult: allConnsStr,
				},
				{
					Src: "y/a", Dst: "x/b",
					ExpResult: allConnsStr,
				},
			},
			Resources: initResources(podInfo1),
			AnpList: initAnpList([]*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: priority100,
						Subject:  allNamespacesSubject,
						Egress:   []v1alpha1.AdminNetworkPolicyEgressRule{egressRuleAllowToXTCP80},
						Ingress:  []v1alpha1.AdminNetworkPolicyIngressRule{ingressRuleAllowFromYUDP80},
					},
				},
			}),
		},
		{
			Name: "ANP with unmatched ingress and egress connection #4",
			// ANP:
			// - subject is all namespaces (x,y)
			// - ingress rule from y : allow UDP80
			// - egress rule to x : deny UDP 80
			//
			// actual table form policy-assistant: (y -> x : UDP 80 is denied)
			// +--------+---------+---------+---------+---------+
			// | TCP/80 |   X/A   |   X/B   |   Y/A   |   Y/B   |
			// | TCP/81 |         |         |         |         |
			// | UDP/80 |         |         |         |         |
			// | UDP/81 |         |         |         |         |
			// +--------+---------+---------+---------+---------+
			// | x/a    | # # # # | . . X . | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | x/b    | . . X . | # # # # | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | y/a    | . . X . | . . X . | # # # # | . . . . |
			// +--------+---------+---------+---------+---------+
			// | y/b    | . . X . | . . X . | . . . . | # # # # |
			// +--------+---------+---------+---------+---------+
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test4_anp_unmatched_ingress_egress_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/a", Dst: "y/b",
					ExpResult: allConnsStr,
				},
				{
					Src: "y/a", Dst: "x/b",
					ExpResult: allButUDP80,
				},
			},
			Resources: initResources(podInfo1),
			AnpList: initAnpList([]*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: priority100,
						Subject:  allNamespacesSubject,
						Egress:   []v1alpha1.AdminNetworkPolicyEgressRule{egressRuleDenyToXUDP80},
						Ingress:  []v1alpha1.AdminNetworkPolicyIngressRule{ingressRuleAllowFromYUDP80},
					},
				},
			}),
		},
		{
			Name: "ANP with unmatched ingress and egress connection #6",
			// ANP:
			// - subject is all namespaces (x,y)
			// - ingress rule from y : deny UDP80
			// - egress rule to x : allow UDP 80
			//
			// actual table form policy-assistant:
			// +--------+---------+---------+---------+---------+
			// | TCP/80 |   X/A   |   X/B   |   Y/A   |   Y/B   |
			// | TCP/81 |         |         |         |         |
			// | UDP/80 |         |         |         |         |
			// | UDP/81 |         |         |         |         |
			// +--------+---------+---------+---------+---------+
			// | x/a    | # # # # | . . . . | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | x/b    | . . . . | # # # # | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | y/a    | . . X . | . . X . | # # # # | . . X . |
			// +--------+---------+---------+---------+---------+
			// | y/b    | . . X . | . . X . | . . X . | # # # # |
			// +--------+---------+---------+---------+---------+
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test6_anp_unmatched_ingress_egress_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/a", Dst: "y/b",
					ExpResult: allConnsStr,
				},
				{
					Src: "y/a", Dst: "x/b",
					ExpResult: allButUDP80,
				},
			},
			Resources: initResources(podInfo1),
			AnpList: initAnpList([]*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: priority100,
						Subject:  allNamespacesSubject,
						Egress:   []v1alpha1.AdminNetworkPolicyEgressRule{egressRuleAllowToXUDP80},
						Ingress:  []v1alpha1.AdminNetworkPolicyIngressRule{ingressRuleDenyFromYUDP80},
					},
				},
			}),
		},
		{
			Name: "ANP with unmatched ingress and egress connection #7",
			// ANP 1:
			// - subject ns : y
			// - priority : 15
			// - egress rule to x :
			//    - allow TCP 80-81
			//    - deny others
			// ANP 2:
			// - subject ns : x
			// - priority : 4
			// - ingress rule from y:
			//      - allow UDP 80
			// what happens from y->x:
			// actual table from policy-assistant:
			// +--------+---------+---------+---------+---------+
			// | TCP/80 |   X/A   |   X/B   |   Y/A   |   Y/B   |
			// | TCP/81 |         |         |         |         |
			// | UDP/80 |         |         |         |         |
			// | UDP/81 |         |         |         |         |
			// +--------+---------+---------+---------+---------+
			// | x/a    | # # # # | . . . . | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | x/b    | . . . . | # # # # | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | y/a    | . . X X | . . X X | # # # # | . . . . |
			// +--------+---------+---------+---------+---------+
			// | y/b    | . . X X | . . X X | . . . . | # # # # |
			// +--------+---------+---------+---------+---------+
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test7_anp_unmatched_ingress_egress_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/a", Dst: "y/b",
					ExpResult: allConnsStr,
				},
				{
					Src: "y/a", Dst: "x/b",
					ExpResult: connTCP80A81,
				},
			},
			Resources: initResources(podInfo1),
			AnpList: initAnpList([]*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 15,
						Subject:  subjectNsY,
						Egress:   []v1alpha1.AdminNetworkPolicyEgressRule{egressRuleAllowToXTCP8081, egressRuleDenyAllToX},
					},
				},
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 4,
						Subject:  subjectNsX,
						Ingress:  []v1alpha1.AdminNetworkPolicyIngressRule{ingressRuleAllowFromYUDP80},
					},
				},
			}),
		},
		{
			Name: "ANP with unmatched ingress and egress connection #13",
			// ANP:
			// - subject is all namespaces (x,y)
			// - ingress rules:
			//    1.pass UDP80 from y
			//    2. deny all from y (deny others)
			// - egress rules to x with (to x : allow only tcp 80)
			//    1. pass TCP 80 to x
			//    2. deny all to x (deny others)
			// what happens from y->x:
			// actual table form policy-assistant:
			// +--------+---------+--- -----+---------+---------+
			// | TCP/80 |   X/A   |   X/B   |   Y/A   |   Y/B   |
			// | TCP/81 |         |         |         |         |
			// | UDP/80 |         |         |         |         |
			// | UDP/81 |         |         |         |         |
			// +--------+---------+---------+---------+---------+
			// | x/a    | # # # # | . X X X | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | x/b    | . X X X | # # # # | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | y/a    | X X X X | X X X X | # # # # | X X . X |
			// +--------+---------+---------+---------+---------+
			// | y/b    | X X X X | X X X X | X X . X | # # # # |
			// +--------+---------+---------+---------+---------+
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test13_anp_unmatched_ingress_egress_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/a", Dst: "y/b",
					ExpResult: allConnsStr,
				},
				{
					Src: "y/a", Dst: "x/b",
					ExpResult: noConns,
				},
			},
			Resources: initResources(podInfo1),
			AnpList: initAnpList([]*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: priority100,
						Subject:  allNamespacesSubject,
						Egress:   []v1alpha1.AdminNetworkPolicyEgressRule{egressRulePassToXTCP80, egressRuleDenyAllToX},
						Ingress:  []v1alpha1.AdminNetworkPolicyIngressRule{ingressRulePassFromYUDP80, ingressRuleDenyAllFromY},
					},
				},
			}),
		},
		{
			Name: "ANP allow specific port - no other restrictions",
			// actual table form policy-assistant:
			// +--------+---------+---------+---------+---------+
			// | TCP/80 |   X/A   |   X/B   |   Y/A   |   Y/B   |
			// | TCP/81 |         |         |         |         |
			// | UDP/80 |         |         |         |         |
			// | UDP/81 |         |         |         |         |
			// +--------+---------+---------+---------+---------+
			// | x/a    | # # # # | . . . . | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | x/b    | . . . . | # # # # | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | y/a    | . . . . | . . . . | # # # # | . . . . |
			// +--------+---------+---------+---------+---------+
			// | y/b    | . . . . | . . . . | . . . . | # # # # |
			// +--------+---------+---------+---------+---------+
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test_anp_allow_specific_port_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/a", Dst: "x/b",
					ExpResult: allConnsStr,
				},
			},
			Resources: initResources(podInfo1),
			AnpList: initAnpList([]*v1alpha1.AdminNetworkPolicy{
				{
					Spec: anpAllowSpecificPort,
				},
			}),
		},
		{
			Name: "ANP deny specific port - no other restrictions",
			// actual table form policy-assistant:
			// +--------+---------+---------+---------+---------+
			// | TCP/80 |   X/A   |   X/B   |   Y/A   |   Y/B   |
			// | TCP/81 |         |         |         |         |
			// | UDP/80 |         |         |         |         |
			// | UDP/81 |         |         |         |         |
			// +--------+---------+---------+---------+---------+
			// | x/a    | # # # # | . . X . | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | x/b    | . . . . | # # # # | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | y/a    | . . . . | . . . . | # # # # | . . . . |
			// +--------+---------+---------+---------+---------+
			// | y/b    | . . . . | . . . . | . . . . | # # # # |
			// +--------+---------+---------+---------+---------+
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test_anp_deny_specific_port_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/a", Dst: "x/b",
					ExpResult: allButUDP80,
				},
			},
			Resources: initResources(podInfo1),
			AnpList: initAnpList([]*v1alpha1.AdminNetworkPolicy{
				{
					Spec: anpDenySpecificPort,
				},
			}),
		},
	}

	BANPConnectivityFromParsedResourcesTest = []ParsedResourcesTest{
		{
			Name:                   "egress",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test1_banp_conn_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/a", Dst: "y/b",
					ExpResult: noConns,
				},
				{
					Src: "0.0.0.0/0", Dst: "y/a",
					ExpResult: allConnsStr,
				},
			},
			Resources: initResources(podInfo1),
			Banp: initBanp(&v1alpha1.BaselineAdminNetworkPolicy{
				Spec: v1alpha1.BaselineAdminNetworkPolicySpec{
					Subject: anpSubject,
					Egress: []v1alpha1.BaselineAdminNetworkPolicyEgressRule{
						{
							Action: v1alpha1.BaselineAdminNetworkPolicyRuleActionDeny,
							To: []v1alpha1.AdminNetworkPolicyEgressPeer{
								{
									Pods: pods5,
								},
							},
						},
					},
				},
			}),
		},
		{
			Name:                   "ingress",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test2_banp_conn_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/a", Dst: "y/b",
					ExpResult: allConnsStr,
				},
				{
					Src: "0.0.0.0/0", Dst: "y/a",
					ExpResult: allConnsStr,
				},
			},
			Resources: initResources(podInfo1),
			Banp: initBanp(&v1alpha1.BaselineAdminNetworkPolicy{
				Spec: v1alpha1.BaselineAdminNetworkPolicySpec{
					Subject: anpSubject,
					Ingress: []v1alpha1.BaselineAdminNetworkPolicyIngressRule{
						{
							Action: v1alpha1.BaselineAdminNetworkPolicyRuleActionDeny,
							From: []v1alpha1.AdminNetworkPolicyIngressPeer{
								{
									Pods: pods5,
								},
							},
						},
					},
				},
			}),
		},
		{
			Name:                   "ordering matters for overlapping rules (order #1)",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test3_banp_conn_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/a", Dst: "y/b",
					ExpResult: noConns,
				},
				{
					Src: "0.0.0.0/0", Dst: "y/a",
					ExpResult: allConnsStr,
				},
			},
			Resources: initResources(podInfo2),
			Banp: initBanp(&v1alpha1.BaselineAdminNetworkPolicy{
				Spec: v1alpha1.BaselineAdminNetworkPolicySpec{
					Subject: allNamespacesSubject,
					Ingress: []v1alpha1.BaselineAdminNetworkPolicyIngressRule{
						{
							Action: v1alpha1.BaselineAdminNetworkPolicyRuleActionAllow,
							From: []v1alpha1.AdminNetworkPolicyIngressPeer{
								{
									Pods: pods4, // y/b
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
			}),
		},
		{
			Name:                   "ordering matters for overlapping rules (order #2)",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test4_banp_conn_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/a", Dst: "y/b",
					ExpResult: noConns,
				},
				{
					Src: "0.0.0.0/0", Dst: "y/a",
					ExpResult: allConnsStr,
				},
			},
			Resources: initResources(podInfo2),
			Banp: initBanp(&v1alpha1.BaselineAdminNetworkPolicy{
				Spec: v1alpha1.BaselineAdminNetworkPolicySpec{
					Subject: allNamespacesSubject,
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
			}),
		},
		{
			Name: "banp allow specific port - no other restrictions",
			// actual table form policy-assistant: (all conns are allowed since no restrictions)
			// +--------+---------+---------+---------+---------+
			// | TCP/80 |   X/A   |   X/B   |   Y/A   |   Y/B   |
			// | TCP/81 |         |         |         |         |
			// | UDP/80 |         |         |         |         |
			// | UDP/81 |         |         |         |         |
			// +--------+---------+---------+---------+---------+
			// | x/a    | # # # # | . . . . | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | x/b    | . . . . | # # # # | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | y/a    | . . . . | . . . . | # # # # | . . . . |
			// +--------+---------+---------+---------+---------+
			// | y/b    | . . . . | . . . . | . . . . | # # # # |
			// +--------+---------+---------+---------+---------+
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test_banp_allow_specific_port_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/a", Dst: "x/b",
					ExpResult: allConnsStr,
				},
			},
			Resources: initResources(podInfo1),
			Banp:      banpAllowSpecificPort,
		},
		{
			Name: "banp deny specific port - no other restrictions",
			// actual table form policy-assistant:
			// +--------+---------+---------+---------+---------+
			// | TCP/80 |   X/A   |   X/B   |   Y/A   |   Y/B   |
			// | TCP/81 |         |         |         |         |
			// | UDP/80 |         |         |         |         |
			// | UDP/81 |         |         |         |         |
			// +--------+---------+---------+---------+---------+
			// | x/a    | # # # # | X . . . | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | x/b    | . . . . | # # # # | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | y/a    | . . . . | . . . . | # # # # | . . . . |
			// +--------+---------+---------+---------+---------+
			// | y/b    | . . . . | . . . . | . . . . | # # # # |
			// +--------+---------+---------+---------+---------+
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test_banp_deny_specific_port_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/a", Dst: "x/b",
					ExpResult: allButTCP80,
				},
			},
			Resources: initResources(podInfo1),
			Banp:      banpDenySpecificPort,
		},
	}

	ANPWithNetPolV1FromParsedResourcesTest = []ParsedResourcesTest{
		{
			Name:                   "ANP allow all over NetPol",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test1_anp_npv1_conn_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/b", Dst: "x/a",
					ExpResult: connTCP80A81UDP80A81,
				},
				{
					Src: "x/b", Dst: "y/a",
					ExpResult: allConnsStr,
				},
			},
			Resources: initResources(podInfo1),
			NpList: initNpList([]*netv1.NetworkPolicy{
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
			}),
			AnpList: initAnpList([]*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 99,
						Subject:  allNamespacesSubject,
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
			}),
		},
		{
			Name:                   "ANP allow some over NetPol",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test2_anp_npv1_conn_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/b", Dst: "x/a",
					ExpResult: connTCP80A81UDP80A81,
				},
				{
					Src: "x/b", Dst: "y/a",
					ExpResult: allConnsStr,
				},
			},
			Resources: initResources(podInfo1),
			NpList: initNpList([]*netv1.NetworkPolicy{
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
			}),
			AnpList: initAnpList([]*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 99,
						Subject:  allNamespacesSubject,
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
			}),
		},
		{
			Name: "ANP with unmatched ingress and egress connection #8",
			// ANP :
			// - subject ns : y
			// - priority : 15
			// - ingress rule allow all from x
			// NP:
			// - ns : x
			// - empty egress (deny all egress)
			// what happens from x->y:
			// actual table from policy-assistant:
			// +--------+---------+---------+---------+---------+
			// | TCP/80 |   X/A   |   X/B   |   Y/A   |   Y/B   |
			// | TCP/81 |         |         |         |         |
			// | UDP/80 |         |         |         |         |
			// | UDP/81 |         |         |         |         |
			// +--------+---------+---------+---------+---------+
			// | x/a    | # # # # | X X X X | X X X X | X X X X |
			// +--------+---------+---------+---------+---------+
			// | x/b    | X X X X | # # # # | X X X X | X X X X |
			// +--------+---------+---------+---------+---------+
			// | y/a    | . . . . | . . . . | # # # # | . . . . |
			// +--------+---------+---------+---------+---------+
			// | y/b    | . . . . | . . . . | . . . . | # # # # |
			// +--------+---------+---------+---------+---------+
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test8_anp_np_unmatched_ingress_egress_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/b", Dst: "y/a",
					ExpResult: noConns,
				},
				{
					Src: "y/b", Dst: "x/a",
					ExpResult: allConnsStr,
				},
			},
			Resources: initResources(podInfo1),
			NpList: initNpList([]*netv1.NetworkPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "x",
						Name:      "base",
					},
					Spec: netv1.NetworkPolicySpec{
						PodSelector: metav1.LabelSelector{},
						PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
					},
				},
			}),
			AnpList: initAnpList([]*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 15,
						Subject:  subjectNsY,
						Ingress:  []v1alpha1.AdminNetworkPolicyIngressRule{ingressRuleAllowAllFromX},
					},
				},
			}),
		},
	}

	BANPWithNetPolV1FromParsedResourcesTest = []ParsedResourcesTest{
		{
			Name:                   "BANP deny all after NetPol",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test1_banp_npv1_conn_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/b", Dst: "x/a",
					ExpResult: connUDP80,
				},
				{
					Src: "0.0.0.0/0", Dst: "x/a",
					ExpResult: noConns,
				},
			},
			// note that resources contain only one namespace x
			Resources: initResources(&PodInfo{Namespaces: []string{"x"}, PodNames: []string{"a", "b"},
				Ports: []int32{80, 81}, Protocols: []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP}}),
			NpList: initNpList([]*netv1.NetworkPolicy{
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
			}),
			Banp: initBanp(&v1alpha1.BaselineAdminNetworkPolicy{
				Spec: v1alpha1.BaselineAdminNetworkPolicySpec{
					Subject: allNamespacesSubject,
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
			}),
		},
	}

	ANPWithBANPFromParsedResourcesTest = []ParsedResourcesTest{
		{
			Name:                   "BANP deny all after ANP",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test1_anp_banp_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/a", Dst: "y/b",
					ExpResult: noConns,
				},
				{
					Src: "0.0.0.0/0", Dst: "y/a",
					ExpResult: allConnsStr,
				},
			},
			Resources: initResources(podInfo1),
			AnpList: initAnpList([]*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: priority100,
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
			}),
			Banp: initBanp(&v1alpha1.BaselineAdminNetworkPolicy{
				Spec: v1alpha1.BaselineAdminNetworkPolicySpec{
					Subject: allNamespacesSubject,
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
			}),
		},
		{
			Name:                   "ANP pass some and allow rest over BANP",
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test2_anp_banp_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/a", Dst: "y/b",
					ExpResult: allConnsStr,
				},
				{
					Src: "0.0.0.0/0", Dst: "y/a",
					ExpResult: allConnsStr,
				},
			},
			Resources: initResources(podInfo1),
			AnpList: initAnpList([]*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: priority100,
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
						Subject:  allNamespacesSubject,
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
			}),
			Banp: initBanp(&v1alpha1.BaselineAdminNetworkPolicy{
				Spec: v1alpha1.BaselineAdminNetworkPolicySpec{
					Subject: allNamespacesSubject,
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
			}),
		},
		{
			Name: "ANP with unmatched ingress and egress connection #3",
			// ANP:
			// - subject is all namespaces (x,y)
			// - ingress rule from y : allow UDP80
			// - egress rule to x : pass UDP 80
			// BANP:
			// - subject : all namespaces
			// - ingress rule : deny all from y
			// what happens from y->x:
			// actual table from policy-assistant:
			// +--------+---------+---------+---------+---------+
			// | TCP/80 |   X/A   |   X/B   |   Y/A   |   Y/B   |
			// | TCP/81 |         |         |         |         |
			// | UDP/80 |         |         |         |         |
			// | UDP/81 |         |         |         |         |
			// +--------+---------+---------+---------+---------+
			// | x/a    | # # # # | . . . . | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | x/b    | . . . . | # # # # | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | y/a    | X X . X | X X . X | # # # # | X X . X |
			// +--------+---------+---------+---------+---------+
			// | y/b    | X X . X | X X . X | X X . X | # # # # |
			// +--------+---------+---------+---------+---------+

			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test3_anp_banp_unmatched_ingress_egress_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/a", Dst: "y/b",
					ExpResult: allConnsStr,
				},
				{
					Src: "y/a", Dst: "x/b",
					ExpResult: connUDP80,
				},
			},
			Resources: initResources(podInfo1),
			AnpList: initAnpList([]*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: priority100,
						Subject:  allNamespacesSubject,
						Egress:   []v1alpha1.AdminNetworkPolicyEgressRule{egressRulePassToXUDP80},
						Ingress:  []v1alpha1.AdminNetworkPolicyIngressRule{ingressRuleAllowFromYUDP80},
					},
				},
			}),
			Banp: banpDenyAllFromY,
		},
		{
			Name: "ANP with unmatched ingress and egress connection #5",
			// ANP:
			// - subject is all namespaces (x,y)
			// - ingress rule from y : Pass UDP80
			// - egress rule to x : Allow UDP 80
			// BANP:
			// - subject : all namespaces
			// - ingress rule : deny all from y
			// what happens from y->x:
			// actual table from policy-assistant: (y->x all conns are denied)
			// +--------+---------+---------+---------+---------+
			// | TCP/80 |   X/A   |   X/B   |   Y/A   |   Y/B   |
			// | TCP/81 |         |         |         |         |
			// | UDP/80 |         |         |         |         |
			// | UDP/81 |         |         |         |         |
			// +--------+---------+---------+---------+---------+
			// | x/a    | # # # # | . . . . | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | x/b    | . . . . | # # # # | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | y/a    | X X X X | X X X X | # # # # | X X X X |
			// +--------+---------+---------+---------+---------+
			// | y/b    | X X X X | X X X X | X X X X | # # # # |
			// +--------+---------+---------+---------+---------+
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test5_anp_banp_unmatched_ingress_egress_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/a", Dst: "y/b",
					ExpResult: allConnsStr,
				},
				{
					Src: "y/a", Dst: "x/b",
					ExpResult: noConns,
				},
			},
			Resources: initResources(podInfo1),
			AnpList: initAnpList([]*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: priority100,
						Subject:  allNamespacesSubject,
						Egress:   []v1alpha1.AdminNetworkPolicyEgressRule{egressRuleAllowToXUDP80},
						Ingress:  []v1alpha1.AdminNetworkPolicyIngressRule{ingressRulePassFromYUDP80},
					},
				},
			}),
			Banp: banpDenyAllFromY,
		},
		{
			Name: "ANP with unmatched ingress and egress connection #11",
			// ANP:
			// - subject is all namespaces (x,y)
			// - ingress rule from y : deny UDP80
			// - egress rule to x : pass UDP 80
			// BANP:
			// - subject : all namespaces
			// - ingress rule : allow all from y
			// what happens from y->x:
			// actual table form policy-assistant: (udp 80 is denied from y -> x)
			// +--------+---------+---------+---------+---------+
			// | TCP/80 |   X/A   |   X/B   |   Y/A   |   Y/B   |
			// | TCP/81 |         |         |         |         |
			// | UDP/80 |         |         |         |         |
			// | UDP/81 |         |         |         |         |
			// +--------+---------+---------+---------+---------+
			// | x/a    | # # # # | . . . . | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | x/b    | . . . . | # # # # | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | y/a    | . . X . | . . X . | # # # # | . . X . |
			// +--------+---------+---------+---------+---------+
			// | y/b    | . . X . | . . X . | . . X . | # # # # |
			// +--------+---------+---------+---------+---------+
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test11_anp_banp_unmatched_ingress_egress_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/a", Dst: "y/b",
					ExpResult: allConnsStr,
				},
				{
					Src: "y/a", Dst: "x/b",
					ExpResult: allButUDP80,
				},
			},
			Resources: initResources(podInfo1),
			AnpList: initAnpList([]*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: priority100,
						Subject:  allNamespacesSubject,
						Egress:   []v1alpha1.AdminNetworkPolicyEgressRule{egressRulePassToXUDP80},
						Ingress:  []v1alpha1.AdminNetworkPolicyIngressRule{ingressRuleDenyFromYUDP80},
					},
				},
			}),
			Banp: banpAllowAllFromY,
		},
		{
			Name: "ANP with unmatched ingress and egress connection #12",
			// ANP:
			// - subject is all namespaces (x,y)
			// - ingress rule from y : pass UDP80
			// - egress rule to x : deny UDP 80
			// BANP:
			// - subject : all namespaces
			// - ingress rule : allow all from y
			// what happens from y->x:
			// actual table form policy-assistant:
			// +--------+---------+---------+---------+---------+
			// | TCP/80 |   X/A   |   X/B   |   Y/A   |   Y/B   |
			// | TCP/81 |         |         |         |         |
			// | UDP/80 |         |         |         |         |
			// | UDP/81 |         |         |         |         |
			// +--------+---------+---------+---------+---------+
			// | x/a    | # # # # | . . X . | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | x/b    | . . X . | # # # # | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | y/a    | . . X . | . . X . | # # # # | . . . . |
			// +--------+---------+---------+---------+---------+
			// | y/b    | . . X . | . . X . | . . . . | # # # # |
			// +--------+---------+---------+---------+---------+
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test12_anp_banp_unmatched_ingress_egress_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/a", Dst: "y/b",
					ExpResult: allConnsStr,
				},
				{
					Src: "y/a", Dst: "x/b",
					ExpResult: allButUDP80,
				},
			},
			Resources: initResources(podInfo1),
			AnpList: initAnpList([]*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: priority100,
						Subject:  allNamespacesSubject,
						Egress:   []v1alpha1.AdminNetworkPolicyEgressRule{egressRuleDenyToXUDP80},
						Ingress:  []v1alpha1.AdminNetworkPolicyIngressRule{ingressRulePassFromYUDP80},
					},
				},
			}),
			Banp: banpAllowAllFromY,
		},
		{
			Name: "ANP with unmatched ingress and egress connection #14",
			// ANP:
			// - subject is all namespaces (x,y)
			// - ingress rules:
			//    1.pass UDP80 from y
			//    2. allow all from y (allow others)
			// - egress rules to x with (to x : allow only tcp 80)
			//    1. pass TCP 80 to x
			//    2. allow all to x (allow others)
			// BANP:
			// - subject : all namespaces
			// - ingress rule : deny all from y
			// what happens from y->x:
			// actual table form policy-assistant:
			// +--------+---------+---------+---------+---------+
			// | TCP/80 |   X/A   |   X/B   |   Y/A   |   Y/B   |
			// | TCP/81 |         |         |         |         |
			// | UDP/80 |         |         |         |         |
			// | UDP/81 |         |         |         |         |
			// +--------+---------+---------+---------+---------+
			// | x/a    | # # # # | . . . . | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | x/b    | . . . . | # # # # | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | y/a    | . . X . | . . X . | # # # # | . . X . |
			// +--------+---------+---------+---------+---------+
			// | y/b    | . . X . | . . X . | . . X . | # # # # |
			// +--------+---------+---------+---------+---------+
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test14_anp_banp_unmatched_ingress_egress_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/a", Dst: "y/b",
					ExpResult: allConnsStr,
				},
				{
					Src: "y/a", Dst: "x/b",
					ExpResult: allButUDP80,
				},
			},
			Resources: initResources(podInfo1),
			AnpList: initAnpList([]*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: priority100,
						Subject:  allNamespacesSubject,
						Egress:   []v1alpha1.AdminNetworkPolicyEgressRule{egressRulePassToXTCP80, egressRuleAllowAllToX},
						Ingress:  []v1alpha1.AdminNetworkPolicyIngressRule{ingressRulePassFromYUDP80, ingressRuleAllowAllFromY},
					},
				},
			}),
			Banp: banpDenyAllFromY,
		},
		{
			Name: "ANP with unmatched ingress and egress connection #9",
			// ANP:
			// - subject is ns:y
			// - egress rule pass all to x
			// BANP:
			// - subject : ns:y
			// - egress rule deny all to x
			// actual table form policy-assistant:
			// +--------+---------+---------+---------+---------+
			// | TCP/80 |   X/A   |   X/B   |   Y/A   |   Y/B   |
			// | TCP/81 |         |         |         |         |
			// | UDP/80 |         |         |         |         |
			// | UDP/81 |         |         |         |         |
			// +--------+---------+---------+---------+---------+
			// | x/a    | # # # # | . . . . | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | x/b    | . . . . | # # # # | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | y/a    | X X X X | X X X X | # # # # | . . . . |
			// +--------+---------+---------+---------+---------+
			// | y/b    | X X X X | X X X X | . . . . | # # # # |
			// +--------+---------+---------+---------+---------+
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test9_anp_banp_unmatched_ingress_egress_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/a", Dst: "y/b",
					ExpResult: allConnsStr,
				},
				{
					Src: "y/a", Dst: "x/b",
					ExpResult: noConns,
				},
			},
			Resources: initResources(podInfo1),
			AnpList: initAnpList([]*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: priority100,
						Subject:  subjectNsY,
						Egress:   []v1alpha1.AdminNetworkPolicyEgressRule{egressRulePassAllToX},
					},
				},
			}),
			Banp: banpDenyAllToX,
		},
		{
			Name: "ANP and BANP allow specific ports - no other restrictions",
			// actual table from policy-assistant:
			// +--------+---------+---------+---------+---------+
			// | TCP/80 |   X/A   |   X/B   |   Y/A   |   Y/B   |
			// | TCP/81 |         |         |         |         |
			// | UDP/80 |         |         |         |         |
			// | UDP/81 |         |         |         |         |
			// +--------+---------+---------+---------+---------+
			// | x/a    | # # # # | . . . . | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | x/b    | . . . . | # # # # | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | y/a    | . . . . | . . . . | # # # # | . . . . |
			// +--------+---------+---------+---------+---------+
			// | y/b    | . . . . | . . . . | . . . . | # # # # |
			// +--------+---------+---------+---------+---------+
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test_anp_banp_allow_specific_ports_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/a", Dst: "x/b",
					ExpResult: allConnsStr,
				},
			},
			Resources: initResources(podInfo1),
			AnpList: initAnpList([]*v1alpha1.AdminNetworkPolicy{
				{
					Spec: anpAllowSpecificPort,
				},
			}),
			Banp: banpAllowSpecificPort,
		},
		{
			Name: "ANP and BANP deny specific ports - no other restrictions",
			// actual table from policy-assistant:
			// +--------+---------+---------+---------+---------+
			// | TCP/80 |   X/A   |   X/B   |   Y/A   |   Y/B   |
			// | TCP/81 |         |         |         |         |
			// | UDP/80 |         |         |         |         |
			// | UDP/81 |         |         |         |         |
			// +--------+---------+---------+---------+---------+
			// | x/a    | # # # # | X . X . | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | x/b    | . . . . | # # # # | . . . . | . . . . |
			// +--------+---------+---------+---------+---------+
			// | y/a    | . . . . | . . . . | # # # # | . . . . |
			// +--------+---------+---------+---------+---------+
			// | y/b    | . . . . | . . . . | . . . . | # # # # |
			// +--------+---------+---------+---------+---------+
			OutputFormat:           output.TextFormat,
			ExpectedOutputFileName: "test_anp_banp_deny_specific_ports_from_parsed_res.txt",
			EvalTests: []EvalAllowedConnTest{
				{
					Src: "x/a", Dst: "x/b",
					ExpResult: allButTCP80UDP80,
				},
			},
			Resources: initResources(podInfo1),
			AnpList: initAnpList([]*v1alpha1.AdminNetworkPolicy{
				{
					Spec: anpDenySpecificPort,
				},
			}),
			Banp: banpDenySpecificPort,
		},
	}
)
