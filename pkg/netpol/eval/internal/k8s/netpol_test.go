/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package k8s

import (
	"testing"

	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

/*func TestCreatePod(t *testing.T) {
	var client client.Client
	client.Clientset = testclient.NewSimpleClientset()

	pod := &v1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:            "nginx",
					Image:           "nginx",
					ImagePullPolicy: "Always",
				},
			},
		},
	}

	_, err := client.CreatePod(pod)
	if err != nil {
		fmt.Print(err.Error())
	}

}*/
/*
const (
	allowAllOnSCTPSerialized = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  creationTimestamp: null
  name: vary-egress-37-0-0-0-19
  namespace: x
spec:
  egress:
  - ports:
    - port: 80
      protocol: TCP
    to:
    - podSelector: {}
    - ipBlock:
        cidr: 192.168.242.213/24
  - ports:
    - port: 53
      protocol: UDP
  podSelector:
    matchLabels:
      pod: a
  policyTypes:
  - Egress`
)*/

var (
	SCTP        = v1.ProtocolSCTP
	TCP         = v1.ProtocolTCP
	UDP         = v1.ProtocolUDP
	Port53      = intstr.FromInt(53)
	Port80      = intstr.FromInt(80)
	Port443     = intstr.FromInt(443)
	Port988     = intstr.FromInt(988)
	Port9001Ref = intstr.FromInt(9001)
	PortHello   = intstr.FromString("hello")
)

func TestNetworkPolicyPortAnalysis(t *testing.T) {
	// tested function: func ruleConnections(rulePorts []netv1.NetworkPolicyPort, dst Peer) ConnectionSet
	dst := PodPeer{Pod: &Pod{Name: "A", Namespace: "default"}}
	dst.Pod.Ports = []v1.ContainerPort{{Name: PortHello.StrVal, ContainerPort: 22, Protocol: "UDP"}}
	// default protocol for containerPort is TCP, if the Protocol is not defined will get a mismatch
	var AllowNamedPortOnProtocol = netv1.NetworkPolicyPort{
		Protocol: &UDP,
		Port:     &PortHello,
	}
	n := &NetworkPolicy{
		&netv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-name",
				Namespace: "test-namespace",
			},
		},
		PolicyExposureWithoutSelectors{},
		PolicyExposureWithoutSelectors{},
		common.Warnings{},
	}
	res, err := n.ruleConnections([]netv1.NetworkPolicyPort{AllowNamedPortOnProtocol}, &dst, 0, false)
	expectedConnStr := "UDP 22"
	if res.String() != expectedConnStr {
		t.Fatalf("mismatch on ruleConnections result: expected %v, got %v", expectedConnStr, res.String())
	}
	if err != nil {
		t.Fatalf("error: %v", err)
	}
}

/*
func TestPodBasic(t *testing.T) {
	decode := scheme.Codecs.UniversalDeserializer().Decode
	stream, _ := ioutils.ReadFile("pod.yaml")
	obj, gKV, _ := decode(stream, nil, nil)
	if gKV.Kind == "Pod" {
		pod := obj.(*v1.Pod)
		fmt.Printf("%v", pod)
	}
}

func TestNetpolBasic(t *testing.T) {

	//set the peer
	peer := Peer{}
	peer.IP = "172.17.0.0"
	peer.PeerType = Iptype

	//get netpol from yaml file
	decode := scheme.Codecs.UniversalDeserializer().Decode
	stream, _ := ioutils.ReadFile("netpol.yaml")
	obj, gKV, _ := decode(stream, nil, nil)
	if gKV.Kind == "NetworkPolicy" {
		np := obj.(*netv1.NetworkPolicy)
		fmt.Printf("%v", np)

		//check for each rule if it selects the peer
		for _, rule := range np.Spec.Ingress {
			rulePeers := rule.From
			//rulePorts := rule.Ports
			res, err := ruleSelectsPeer(rulePeers, peer)
			fmt.Printf("ingress res %v, err %v", res, err)
		}
		for _, rule := range np.Spec.Egress {
			rulePeers := rule.To
			res, err := ruleSelectsPeer(rulePeers, peer)
			fmt.Printf("egress res %v, err %v", res, err)
		}
	}
	fmt.Printf("done")
}
*/
/*
https://medium.com/@harshjniitr/reading-and-writing-k8s-resource-as-yaml-in-golang-81dc8c7ea800

import (
     "k8s.io/client-go/kubernetes/scheme"
      corev1 "k8s.io/api/core/v1"
      apiextv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
     "k8s.io/apimachinery/pkg/runtime/serializer"
)
sch := runtime.NewScheme()
_ = scheme.AddToScheme(sch)
_ = apiextv1beta1.AddToScheme(sch)
decode := serializer.NewCodecFactory(sch).UniversalDeserializer().Decode
stream, _ :=ioutils.ReadFile("crd.yaml")
obj, gKV, _ := decode(stream, nil, nil)
if gKV.Kind == "CustomResourceDefinition" {
           pod := obj.(*apiextv1beta1.CustomResourceDefinition)
}
*/
