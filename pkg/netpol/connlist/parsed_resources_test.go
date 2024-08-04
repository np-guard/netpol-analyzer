package connlist

import (
	"fmt"
	"strings"
	"testing"

	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/np-guard/netpol-analyzer/pkg/internal/output"
	"github.com/np-guard/netpol-analyzer/pkg/internal/testutils"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/parser"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/network-policy-api/apis/v1alpha1"
)

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

type podInfo struct {
	namespaces []string
	podNames   []string
	ports      []int
	protocols  []v1.Protocol
}

type ParsedResourcesTest struct {
	Name                   string
	OutputFormat           string
	ExpectedOutputFileName string
	PodResources           podInfo
	ANpList                []*v1alpha1.AdminNetworkPolicy
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

func (test *ParsedResourcesTest) InitParsedResourcesTest() {
	var genCnt = 0
	test.TestInfo = fmt.Sprintf("test: %q, output format: %q", test.Name, test.OutputFormat)
	for _, ns := range test.PodResources.namespaces {
		parsedNs := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, Labels: map[string]string{"ns": ns}}}
		k8sObj := parser.CreateNamespaceK8sObject(parsedNs)
		test.Resources = append(test.Resources, k8sObj)
		for _, pod := range test.PodResources.podNames {
			parsedPod := newDefaultPod(ns, pod, test.PodResources.ports, test.PodResources.protocols)
			k8sObj := parser.CreatePodK8sObject(&parsedPod)
			test.Resources = append(test.Resources, k8sObj)
		}
	}
	for _, np := range test.NpList {
		addMetaData(&np.ObjectMeta, &genCnt)
		k8sObj := parser.CreateNetwordPolicyK8sObject(np)
		test.Resources = append(test.Resources, k8sObj)
	}
	for _, anp := range test.ANpList {
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

func runParsedResourcesEvalTests(t *testing.T, testList []ParsedResourcesTest) {
	t.Helper()
	for i := 0; i < len(testList); i++ {
		test := &testList[i]
		t.Run(test.Name, func(t *testing.T) {
			//t.Parallel()  // Tanya: temp commenting
			test.InitParsedResourcesTest()
			if test.Banp != nil { // Tanya - remove this 'if' whenever BaselineAdminNetworkPolicy is implemented
				return // Skip tests with BANP, until implemented
			}
			pe, err := eval.NewPolicyEngineWithObjects(test.Resources)

			require.Nil(t, err, test.TestInfo)
			peerList, err := pe.GetPeersList()
			require.Nil(t, err, test.TestInfo)
			peers := make([]Peer, len(peerList))
			for i, p := range peerList {
				peers[i] = p
			}
			connsRes := make([]Peer2PeerConnection, 0)
			for _, src := range peerList {
				for _, dst := range peerList {
					if (src.String() == dst.String()) || (src.IsPeerIPType() && dst.IsPeerIPType()) {
						continue
					}
					allowedConns, err := pe.AllAllowedConnectionsBetweenWorkloadPeers(src, dst)
					require.Nil(t, err, test.TestInfo)
					if allowedConns.IsEmpty() {
						continue
					}
					p2pConnection := &connection{
						src:               src,
						dst:               dst,
						allConnections:    allowedConns.AllConnections(),
						protocolsAndPorts: allowedConns.ProtocolsAndPortsMap(),
					}
					connsRes = append(connsRes, p2pConnection)
				}
			}
			connsFormatter, err := getFormatter(test.OutputFormat, peers)
			require.Nil(t, err, test.TestInfo)
			out, err := connsFormatter.writeOutput(connsRes)
			require.Nil(t, err, test.TestInfo)
			fmt.Printf("The result of %q:\n%s\n\n", test.TestInfo, out)
			testutils.CheckActualVsExpectedOutputMatch(t, test.ExpectedOutputFileName, out,
				test.TestInfo, currentPkg)

		})
	}
}

func TestAllParsedResourcesEvalTests(t *testing.T) {
	runParsedResourcesEvalTests(t, GetANPConnectivityFromParsedResourcesTest())
	runParsedResourcesEvalTests(t, GetBANPConnectivityFromParsedResourcesTest())
	runParsedResourcesEvalTests(t, GetANPWithNetPolV1FromParsedResourcesTest())
	runParsedResourcesEvalTests(t, GetBANPWithNetPolV1FromParsedResourcesTest())
	runParsedResourcesEvalTests(t, GetANPWithBANPFromParsedResourcesTest())
}

func runParsedResourcesConnlistTests(t *testing.T, testList []ParsedResourcesTest) {
	t.Helper()
	for i := 0; i < len(testList); i++ {
		test := &testList[i]
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			test.InitParsedResourcesTest()
			analyzer := NewConnlistAnalyzer(WithOutputFormat(test.OutputFormat))
			res, _, err := analyzer.connslistFromParsedResources(test.Resources)
			require.Nil(t, err, test.TestInfo)
			out, err := analyzer.ConnectionsListToString(res)
			fmt.Printf("The result of %s:\n%s\n\n", test.TestInfo, out)
			require.Nil(t, err, test.TestInfo)
			if test.Banp == nil { // Tanya - remove this 'if' whenever BaselineAdminNetworkPolicy is implemented
				testutils.CheckActualVsExpectedOutputMatch(t, test.ExpectedOutputFileName, out,
					test.TestInfo, currentPkg)
			}
		})
	}
}

func TestAllParsedResourcesConnlistTests(t *testing.T) {
	runParsedResourcesConnlistTests(t, GetANPConnectivityFromParsedResourcesTest())
	runParsedResourcesConnlistTests(t, GetBANPConnectivityFromParsedResourcesTest())
	runParsedResourcesConnlistTests(t, GetANPWithNetPolV1FromParsedResourcesTest())
	runParsedResourcesConnlistTests(t, GetBANPWithNetPolV1FromParsedResourcesTest())
	runParsedResourcesConnlistTests(t, GetANPWithBANPFromParsedResourcesTest())
}

//////////////////////////////////// The following tests are taken from /////////////////////////////////////
// https://github.com/kubernetes-sigs/network-policy-api/blob/main/cmd/policy-assistant/test/integration/integration_test.go

func GetANPConnectivityFromParsedResourcesTest() []ParsedResourcesTest {
	return []ParsedResourcesTest{
		{
			Name:                   "egress port number protocol unspecified",
			OutputFormat:           string(output.TextFormat),
			ExpectedOutputFileName: "test1_anp_conn_from_parsed_res.txt",
			PodResources:           podInfo{[]string{"x", "y"}, []string{"a", "b"}, []int{80, 81}, []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP}},
			ANpList: []*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 100,
						Subject: v1alpha1.AdminNetworkPolicySubject{
							Pods: &v1alpha1.NamespacedPod{
								NamespaceSelector: metav1.LabelSelector{
									MatchLabels: map[string]string{"ns": "x"},
								},
								PodSelector: metav1.LabelSelector{
									MatchLabels: map[string]string{"pod": "a"},
								},
							},
						},
						Egress: []v1alpha1.AdminNetworkPolicyEgressRule{
							{
								Action: v1alpha1.AdminNetworkPolicyRuleActionDeny,
								To: []v1alpha1.AdminNetworkPolicyEgressPeer{
									{
										Pods: &v1alpha1.NamespacedPod{
											NamespaceSelector: metav1.LabelSelector{
												MatchLabels: map[string]string{"ns": "x"},
											},
											PodSelector: metav1.LabelSelector{
												MatchLabels: map[string]string{"pod": "b"},
											},
										},
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
			OutputFormat:           string(output.TextFormat),
			ExpectedOutputFileName: "test2_anp_conn_from_parsed_res.txt",
			PodResources:           podInfo{[]string{"x", "y"}, []string{"a", "b"}, []int{80, 81}, []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP}},
			ANpList: []*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 100,
						Subject: v1alpha1.AdminNetworkPolicySubject{
							Pods: &v1alpha1.NamespacedPod{
								NamespaceSelector: metav1.LabelSelector{
									MatchLabels: map[string]string{"ns": "x"},
								},
								PodSelector: metav1.LabelSelector{
									MatchLabels: map[string]string{"pod": "a"},
								},
							},
						},
						Ingress: []v1alpha1.AdminNetworkPolicyIngressRule{
							{
								Action: v1alpha1.AdminNetworkPolicyRuleActionDeny,
								From: []v1alpha1.AdminNetworkPolicyIngressPeer{
									{
										Pods: &v1alpha1.NamespacedPod{
											NamespaceSelector: metav1.LabelSelector{
												MatchLabels: map[string]string{"ns": "x"},
											},
											PodSelector: metav1.LabelSelector{
												MatchLabels: map[string]string{"pod": "b"},
											},
										},
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
			OutputFormat:           string(output.TextFormat),
			ExpectedOutputFileName: "test3_anp_conn_from_parsed_res.txt",
			PodResources:           podInfo{[]string{"x", "y"}, []string{"a", "b"}, []int{80, 81}, []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP}},
			ANpList: []*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 100,
						Subject: v1alpha1.AdminNetworkPolicySubject{
							Pods: &v1alpha1.NamespacedPod{
								NamespaceSelector: metav1.LabelSelector{
									MatchLabels: map[string]string{"ns": "x"},
								},
								PodSelector: metav1.LabelSelector{
									MatchLabels: map[string]string{"pod": "a"},
								},
							},
						},
						Ingress: []v1alpha1.AdminNetworkPolicyIngressRule{
							{
								Action: v1alpha1.AdminNetworkPolicyRuleActionDeny,
								From: []v1alpha1.AdminNetworkPolicyIngressPeer{
									{
										Pods: &v1alpha1.NamespacedPod{
											NamespaceSelector: metav1.LabelSelector{
												MatchLabels: map[string]string{"ns": "x"},
											},
											PodSelector: metav1.LabelSelector{
												MatchLabels: map[string]string{"pod": "b"},
											},
										},
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
			OutputFormat:           string(output.TextFormat),
			ExpectedOutputFileName: "test4_anp_conn_from_parsed_res.txt",
			PodResources: podInfo{[]string{"x", "y", "z"}, []string{"a", "b", "c"}, []int{80, 81},
				[]v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP}},
			ANpList: []*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 100,
						Subject: v1alpha1.AdminNetworkPolicySubject{
							Pods: &v1alpha1.NamespacedPod{
								NamespaceSelector: metav1.LabelSelector{
									MatchLabels: map[string]string{"ns": "x"},
								},
								PodSelector: metav1.LabelSelector{
									MatchLabels: map[string]string{"pod": "a"},
								},
							},
						},
						Ingress: []v1alpha1.AdminNetworkPolicyIngressRule{
							{
								Action: v1alpha1.AdminNetworkPolicyRuleActionDeny,
								Ports: &([]v1alpha1.AdminNetworkPolicyPort{
									{
										PortRange: &v1alpha1.PortRange{
											Protocol: v1.ProtocolTCP,
											Start:    80,
											End:      81,
										},
									},
								}),
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
			OutputFormat:           string(output.TextFormat),
			ExpectedOutputFileName: "test5_anp_conn_from_parsed_res.txt",
			PodResources:           podInfo{[]string{"x", "y"}, []string{"a", "b"}, []int{80, 81}, []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP}},
			ANpList: []*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 100,
						Subject: v1alpha1.AdminNetworkPolicySubject{
							Pods: &v1alpha1.NamespacedPod{
								NamespaceSelector: metav1.LabelSelector{
									MatchLabels: map[string]string{"ns": "x"},
								},
								PodSelector: metav1.LabelSelector{
									MatchLabels: map[string]string{"pod": "a"},
								},
							},
						},
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
								Ports: &([]v1alpha1.AdminNetworkPolicyPort{
									{
										PortNumber: &v1alpha1.Port{
											Port:     80,
											Protocol: v1.ProtocolUDP,
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
			Name:                   "ordering matters for overlapping rules (order #1)",
			OutputFormat:           string(output.TextFormat),
			ExpectedOutputFileName: "test6_anp_conn_from_parsed_res.txt",
			PodResources:           podInfo{[]string{"x", "y"}, []string{"a", "b"}, []int{80, 81}, []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP}},
			ANpList: []*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 100,
						Subject: v1alpha1.AdminNetworkPolicySubject{
							Pods: &v1alpha1.NamespacedPod{
								NamespaceSelector: metav1.LabelSelector{
									MatchLabels: map[string]string{"ns": "x"},
								},
								PodSelector: metav1.LabelSelector{
									MatchLabels: map[string]string{"pod": "a"},
								},
							},
						},
						Ingress: []v1alpha1.AdminNetworkPolicyIngressRule{
							{
								Action: v1alpha1.AdminNetworkPolicyRuleActionAllow,
								From: []v1alpha1.AdminNetworkPolicyIngressPeer{
									{
										Pods: &v1alpha1.NamespacedPod{
											NamespaceSelector: metav1.LabelSelector{
												MatchLabels: map[string]string{"ns": "y"},
											},
											PodSelector: metav1.LabelSelector{
												MatchLabels: map[string]string{"pod": "a"},
											},
										},
									},
								},
								Ports: &([]v1alpha1.AdminNetworkPolicyPort{
									{
										PortNumber: &v1alpha1.Port{
											Port:     80,
											Protocol: v1.ProtocolUDP,
										},
									},
								}),
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
								Ports: &([]v1alpha1.AdminNetworkPolicyPort{
									{
										PortNumber: &v1alpha1.Port{
											Port:     80,
											Protocol: v1.ProtocolUDP,
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
			Name:                   "ordering matters for overlapping rules (order #2)",
			OutputFormat:           string(output.TextFormat),
			ExpectedOutputFileName: "test7_anp_conn_from_parsed_res.txt",
			PodResources:           podInfo{[]string{"x", "y"}, []string{"a", "b"}, []int{80, 81}, []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP}},
			ANpList: []*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 100,
						Subject: v1alpha1.AdminNetworkPolicySubject{
							Pods: &v1alpha1.NamespacedPod{
								NamespaceSelector: metav1.LabelSelector{
									MatchLabels: map[string]string{"ns": "x"},
								},
								PodSelector: metav1.LabelSelector{
									MatchLabels: map[string]string{"pod": "a"},
								},
							},
						},
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
								Ports: &([]v1alpha1.AdminNetworkPolicyPort{
									{
										PortNumber: &v1alpha1.Port{
											Port:     80,
											Protocol: v1.ProtocolUDP,
										},
									},
								}),
							},
							{
								Action: v1alpha1.AdminNetworkPolicyRuleActionAllow,
								From: []v1alpha1.AdminNetworkPolicyIngressPeer{
									{
										Pods: &v1alpha1.NamespacedPod{
											NamespaceSelector: metav1.LabelSelector{
												MatchLabels: map[string]string{"ns": "y"},
											},
											PodSelector: metav1.LabelSelector{
												MatchLabels: map[string]string{"pod": "a"},
											},
										},
									},
								},
								Ports: &([]v1alpha1.AdminNetworkPolicyPort{
									{
										PortNumber: &v1alpha1.Port{
											Port:     80,
											Protocol: v1.ProtocolUDP,
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
			Name:                   "deny all egress",
			OutputFormat:           string(output.TextFormat),
			ExpectedOutputFileName: "test8_anp_conn_from_parsed_res.txt",
			PodResources:           podInfo{[]string{"x", "y"}, []string{"a", "b"}, []int{80, 81}, []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP}},
			ANpList: []*v1alpha1.AdminNetworkPolicy{
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
								Ports: &([]v1alpha1.AdminNetworkPolicyPort{
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
								}),
							},
						},
					},
				},
			},
		},
		{
			Name:                   "multiple ANPs (priority order #1)",
			OutputFormat:           string(output.TextFormat),
			ExpectedOutputFileName: "test9_anp_conn_from_parsed_res.txt",
			PodResources:           podInfo{[]string{"x", "y"}, []string{"a", "b"}, []int{80, 81}, []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP}},
			ANpList: []*v1alpha1.AdminNetworkPolicy{
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
								Ports: &([]v1alpha1.AdminNetworkPolicyPort{
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
								}),
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
								Ports: &([]v1alpha1.AdminNetworkPolicyPort{
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
								}),
							},
						},
					},
				},
			},
		},
		{
			Name:                   "multiple ANPs (priority order #2)",
			OutputFormat:           string(output.TextFormat),
			ExpectedOutputFileName: "test10_anp_conn_from_parsed_res.txt",
			PodResources:           podInfo{[]string{"x", "y"}, []string{"a", "b"}, []int{80, 81}, []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP}},
			ANpList: []*v1alpha1.AdminNetworkPolicy{
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
								Ports: &([]v1alpha1.AdminNetworkPolicyPort{
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
								}),
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
								Ports: &([]v1alpha1.AdminNetworkPolicyPort{
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
								}),
							},
						},
					},
				},
			},
		},
	}
}

func GetBANPConnectivityFromParsedResourcesTest() []ParsedResourcesTest {
	return []ParsedResourcesTest{
		{
			Name:                   "egress",
			OutputFormat:           string(output.TextFormat),
			ExpectedOutputFileName: "test1_banp_conn_from_parsed_res.txt",
			PodResources:           podInfo{[]string{"x", "y"}, []string{"a", "b"}, []int{80, 81}, []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP}},
			Banp: &v1alpha1.BaselineAdminNetworkPolicy{
				Spec: v1alpha1.BaselineAdminNetworkPolicySpec{
					Subject: v1alpha1.AdminNetworkPolicySubject{
						Pods: &v1alpha1.NamespacedPod{
							NamespaceSelector: metav1.LabelSelector{
								MatchLabels: map[string]string{"ns": "x"},
							},
							PodSelector: metav1.LabelSelector{
								MatchLabels: map[string]string{"pod": "a"},
							},
						},
					},
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
			OutputFormat:           string(output.TextFormat),
			ExpectedOutputFileName: "test2_banp_conn_from_parsed_res.txt",
			PodResources:           podInfo{[]string{"x", "y"}, []string{"a", "b"}, []int{80, 81}, []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP}},
			Banp: &v1alpha1.BaselineAdminNetworkPolicy{
				Spec: v1alpha1.BaselineAdminNetworkPolicySpec{
					Subject: v1alpha1.AdminNetworkPolicySubject{
						Pods: &v1alpha1.NamespacedPod{
							NamespaceSelector: metav1.LabelSelector{
								MatchLabels: map[string]string{"ns": "x"},
							},
							PodSelector: metav1.LabelSelector{
								MatchLabels: map[string]string{"pod": "a"},
							},
						},
					},
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
			OutputFormat:           string(output.TextFormat),
			ExpectedOutputFileName: "test3_banp_conn_from_parsed_res.txt",
			PodResources:           podInfo{[]string{"x", "y"}, []string{"a", "b"}, []int{80}, []v1.Protocol{v1.ProtocolTCP}},
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
									Pods: &v1alpha1.NamespacedPod{
										NamespaceSelector: metav1.LabelSelector{
											MatchLabels: map[string]string{"ns": "y"},
										},
										PodSelector: metav1.LabelSelector{
											MatchLabels: map[string]string{"pod": "b"},
										},
									},
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
			OutputFormat:           string(output.TextFormat),
			ExpectedOutputFileName: "test4_banp_conn_from_parsed_res.txt",
			PodResources:           podInfo{[]string{"x", "y"}, []string{"a", "b"}, []int{80}, []v1.Protocol{v1.ProtocolTCP}},
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
									Pods: &v1alpha1.NamespacedPod{
										NamespaceSelector: metav1.LabelSelector{
											MatchLabels: map[string]string{"ns": "y"},
										},
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
	}
}

func GetANPWithNetPolV1FromParsedResourcesTest() []ParsedResourcesTest {
	return []ParsedResourcesTest{
		{
			Name:                   "ANP allow all over NetPol",
			OutputFormat:           string(output.TextFormat),
			ExpectedOutputFileName: "test1_anp_npv1_conn_from_parsed_res.txt",
			PodResources:           podInfo{[]string{"x", "y"}, []string{"a", "b"}, []int{80, 81}, []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP}},
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
			ANpList: []*v1alpha1.AdminNetworkPolicy{
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
								Ports: &([]v1alpha1.AdminNetworkPolicyPort{
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
								}),
							},
						},
					},
				},
			},
		},
		{
			Name:                   "ANP allow some over NetPol",
			OutputFormat:           string(output.TextFormat),
			ExpectedOutputFileName: "test2_anp_npv1_conn_from_parsed_res.txt",
			PodResources:           podInfo{[]string{"x", "y"}, []string{"a", "b"}, []int{80, 81}, []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP}},
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
			ANpList: []*v1alpha1.AdminNetworkPolicy{
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
								Ports: &([]v1alpha1.AdminNetworkPolicyPort{
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
								}),
							},
						},
					},
				},
			},
		},
	}
}

func GetBANPWithNetPolV1FromParsedResourcesTest() []ParsedResourcesTest {
	return []ParsedResourcesTest{
		{
			Name:                   "BANP deny all after NetPol",
			OutputFormat:           string(output.TextFormat),
			ExpectedOutputFileName: "test1_banp_npv1_conn_from_parsed_res.txt",
			PodResources:           podInfo{[]string{"x"}, []string{"a", "b"}, []int{80, 81}, []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP}},
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
}

func GetANPWithBANPFromParsedResourcesTest() []ParsedResourcesTest {
	return []ParsedResourcesTest{
		{
			Name:                   "BANP deny all after ANP",
			OutputFormat:           string(output.TextFormat),
			ExpectedOutputFileName: "test1_anp_banp_from_parsed_res.txt",
			PodResources:           podInfo{[]string{"x", "y"}, []string{"a", "b"}, []int{80, 81}, []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP}},
			ANpList: []*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 100,
						Subject: v1alpha1.AdminNetworkPolicySubject{
							Pods: &v1alpha1.NamespacedPod{
								NamespaceSelector: metav1.LabelSelector{
									MatchLabels: map[string]string{"ns": "x"},
								},
								PodSelector: metav1.LabelSelector{
									MatchLabels: map[string]string{"pod": "a"},
								},
							},
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
								Ports: &([]v1alpha1.AdminNetworkPolicyPort{
									{
										PortNumber: &v1alpha1.Port{
											Protocol: v1.ProtocolUDP,
											Port:     80,
										},
									},
								}),
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
			OutputFormat:           string(output.TextFormat),
			ExpectedOutputFileName: "test2_anp_banp_from_parsed_res.txt",
			PodResources:           podInfo{[]string{"x", "y"}, []string{"a", "b"}, []int{80, 81}, []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP}},
			ANpList: []*v1alpha1.AdminNetworkPolicy{
				{
					Spec: v1alpha1.AdminNetworkPolicySpec{
						Priority: 100,
						Subject: v1alpha1.AdminNetworkPolicySubject{
							Pods: &v1alpha1.NamespacedPod{
								NamespaceSelector: metav1.LabelSelector{
									MatchLabels: map[string]string{"ns": "x"},
								},
								PodSelector: metav1.LabelSelector{
									MatchLabels: map[string]string{"pod": "a"},
								},
							},
						},
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
								Ports: &([]v1alpha1.AdminNetworkPolicyPort{
									{
										PortNumber: &v1alpha1.Port{
											Protocol: v1.ProtocolUDP,
											Port:     80,
										},
									},
								}),
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
}
