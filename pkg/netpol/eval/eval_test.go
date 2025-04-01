/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package eval

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"sort"
	"strings"
	"testing"

	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/yaml"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/netpol-analyzer/pkg/internal/output"
	"github.com/np-guard/netpol-analyzer/pkg/internal/testutils"
	"github.com/np-guard/netpol-analyzer/pkg/logger"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/fsscanner"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/parser"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/examples"
)

const (
	allowAllOnSCTPSerialized = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  creationTimestamp: null
  name: vary-egress-37-0-0-0-19
  namespace: default
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
      app: web
  policyTypes:
  - Egress`

	podB = `
apiVersion: v1
kind: Pod
metadata:
  name: b
  namespace: default
  labels:
    app: web
    role: monitoring
spec:
  containers:
  - name: nginx
    image: nginx:1.14.2
    ports:
    - containerPort: 80
status:
  podIPs:
  - ip: 192.168.49.2    
  hostIP: 192.168.49.2`

	podC = `
  apiVersion: v1
  kind: Pod
  metadata:
    name: c
    namespace: default
    labels:
      app: apiserver
  spec:
    containers:
    - name: nginx
      image: nginx:1.14.2
      ports:
      - containerPort: 80
  status:
    podIPs:
    - ip: 192.168.49.2    
    hostIP: 192.168.49.2`

	podD = `
apiVersion: v1
kind: Pod
metadata:
  name: d
  namespace: operations
  labels:
    type: monitoring
spec:
  containers:
  - name: nginx
    image: nginx:1.14.2
    ports:
    - containerPort: 80
status:
  podIPs:
  - ip: 192.168.49.2    
  hostIP: 192.168.49.2`
)

func netpolFromYaml(netpolYamlStr string) (*netv1.NetworkPolicy, error) {
	netpol := netv1.NetworkPolicy{}
	err := yaml.Unmarshal([]byte(netpolYamlStr), &netpol)
	if err != nil {
		return nil, err
	}
	return &netpol, nil
}

func podFromYaml(podYamlStr string) (*v1.Pod, error) {
	podObj := v1.Pod{}
	err := yaml.Unmarshal([]byte(podYamlStr), &podObj)
	if err != nil {
		return nil, err
	}
	return &podObj, nil
}

func LabelString(labels map[string]string) string {
	// 1. first, sort the keys so we get a deterministic answer
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})
	// 2. now use the sorted keys to generate chunks
	chunks := make([]string, 0, len(labels))
	for _, key := range keys {
		chunks = append(chunks, key, labels[key])
	}
	// 3. join
	return strings.Join(chunks, "-")
}

func label(key, val string) map[string]string {
	return map[string]string{key: val}
}

// https://github.com/ahmetb/kubernetes-network-policy-recipes/blob/master/01-deny-all-traffic-to-an-application.md
/*
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: web-deny-all
spec:
  podSelector:
    matchLabels:
      app: web
  ingress: []
*/
func AllowNothingTo(namespace string, toLabels map[string]string) *netv1.NetworkPolicy {
	return &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("allow-nothing-to-%s", LabelString(toLabels)),
			Namespace: namespace,
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: toLabels},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
		},
	}
}

// https://github.com/ahmetb/kubernetes-network-policy-recipes/blob/master/02a-allow-all-traffic-to-an-application.md
/*
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: web-allow-all
  Namespace: default
spec:
  podSelector:
    matchLabels:
      app: web
  ingress:
  - {}
*/
func AllowAllTo(namespace string, toLabels map[string]string) *netv1.NetworkPolicy {
	return &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("allow-all-to-%s", LabelString(toLabels)),
			Namespace: namespace,
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: toLabels,
			},
			Ingress: []netv1.NetworkPolicyIngressRule{
				{},
			},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
		},
	}
}

/*
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:

	name: api-allow-5000

spec:

	podSelector:
	  matchLabels:
	    app: apiserver
	ingress:
	- ports:
	  - port: 5000
	  from:
	  - podSelector:
	      matchLabels:
	        role: monitoring
*/
func AllowSpecificPortTo(namespace string, fromLabels, targetLabels map[string]string, targetPort int) *netv1.NetworkPolicy {
	portRef := intstr.FromInt(targetPort)
	return &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("allow-specific-port-from-%s-to-%s", LabelString(fromLabels), LabelString(targetLabels)),
			Namespace: namespace,
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: targetLabels,
			},
			Ingress: []netv1.NetworkPolicyIngressRule{
				{
					Ports: []netv1.NetworkPolicyPort{
						{Port: &portRef},
					},
					From: []netv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: fromLabels,
							},
						},
					},
				},
			},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
		},
	}
}

// https://github.com/ahmetb/kubernetes-network-policy-recipes/blob/master/05-allow-traffic-from-all-namespaces.md
/*
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  Namespace: secondary
  name: web-allow-all-namespaces
spec:
  podSelector:
    matchLabels:
      app: web
  ingress:
  - from:
    - namespaceSelector: {}
*/
func AllowAllToVersion2(namespace string, targetLabels map[string]string) *netv1.NetworkPolicy {
	return &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("allow-all-to-version2-%s", LabelString(targetLabels)),
			Namespace: namespace,
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: targetLabels,
			},
			Ingress: []netv1.NetworkPolicyIngressRule{
				{
					From: []netv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{},
						},
					},
				},
			},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
		},
	}
}

// https://github.com/ahmetb/kubernetes-network-policy-recipes/blob/master/07-allow-traffic-from-some-pods-in-another-namespace.md
/*
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: web-allow-all-ns-monitoring
  Namespace: default
spec:
  podSelector:
    matchLabels:
      app: web
  ingress:
    - from:
      - namespaceSelector:     # chooses all pods in namespaces labeled with team=operations
          matchLabels:
            team: operations
        podSelector:           # chooses pods with type=monitoring
          matchLabels:
            type: monitoring
*/
func AllowFromDifferentNamespaceWithLabelsTo(
	namespace string,
	fromLabels, namespaceLabels, toLabels map[string]string) *netv1.NetworkPolicy {
	return &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("allow-from-namespace-with-labels-%s-to-%s", LabelString(fromLabels), LabelString(toLabels)),
			Namespace: namespace,
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: toLabels,
			},
			Ingress: []netv1.NetworkPolicyIngressRule{
				{
					From: []netv1.NetworkPolicyPeer{
						{
							PodSelector:       &metav1.LabelSelector{MatchLabels: fromLabels},
							NamespaceSelector: &metav1.LabelSelector{MatchLabels: namespaceLabels},
						},
					},
				},
			},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
		},
	}
}

// https://github.com/ahmetb/kubernetes-network-policy-recipes/blob/master/04-deny-traffic-from-other-namespaces.md
/*
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  Namespace: secondary
  name: deny-from-other-namespaces
spec:
  podSelector:
    matchLabels:
  ingress:
  - from:
    - podSelector: {}
*/
func AllowAllWithinNamespace(namespace string) *netv1.NetworkPolicy {
	return &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-all-within-namespace",
			Namespace: namespace,
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{},
			},
			Ingress: []netv1.NetworkPolicyIngressRule{
				{
					From: []netv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{},
						},
					},
				},
			},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
		},
	}
}

/*
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:

	Namespace: secondary
	name: web-allow-all-namespaces

spec:

	podSelector:
	  matchLabels:
	    app: web
	ingress:
	- from:
*/
func AllowAllToVersion3(namespace string, targetLabels map[string]string) *netv1.NetworkPolicy {
	return &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("allow-all-to-version3-%s", LabelString(targetLabels)),
			Namespace: namespace,
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: targetLabels,
			},
			Ingress: []netv1.NetworkPolicyIngressRule{
				{From: nil},
			},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
		},
	}
}

func AllowAllToVersion4(namespace string, toLabels map[string]string) *netv1.NetworkPolicy {
	return &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("allow-all-to-version4-%s", LabelString(toLabels)),
			Namespace: namespace,
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: toLabels,
			},
			Ingress: []netv1.NetworkPolicyIngressRule{
				{
					From: []netv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{}, NamespaceSelector: &metav1.LabelSelector{}}},
				},
			},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
		},
	}
}

// https://github.com/ahmetb/kubernetes-network-policy-recipes/blob/master/03-deny-all-non-whitelisted-traffic-in-the-namespace.md
/*
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: default-deny-all
  Namespace: default
spec:
  podSelector: {}
  ingress: []
*/
func AllowNothingToAnything(namespace string) *netv1.NetworkPolicy {
	return &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-nothing-to-anything",
			Namespace: namespace,
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			Ingress:     []netv1.NetworkPolicyIngressRule{},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
		},
	}
}

// https://github.com/ahmetb/kubernetes-network-policy-recipes/blob/master/02-limit-traffic-to-an-application.md
/*
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: api-allow
spec:
  podSelector:
    matchLabels:
      app: bookstore
      role: api
  ingress:
  - from:
      - podSelector:
          matchLabels:
            app: bookstore
*/
func AllowFromTo(namespace string, fromLabels, toLabels map[string]string) *netv1.NetworkPolicy {
	return &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("allow-from-%s-to-%s", LabelString(fromLabels), LabelString(toLabels)),
			Namespace: namespace,
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: toLabels},
			Ingress: []netv1.NetworkPolicyIngressRule{
				{
					From: []netv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{MatchLabels: fromLabels},
						},
					},
				},
			},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
		},
	}
}

// https://github.com/ahmetb/kubernetes-network-policy-recipes/blob/master/08-allow-external-traffic.md
/*
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: web-allow-external
spec:
  podSelector:
    matchLabels:
      app: web
  ingress:
  - from: []
*/
func AllowFromAnywhere(namespace string, targetLabels map[string]string) *netv1.NetworkPolicy {
	return &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("allow-from-anywhere-to-%s", LabelString(targetLabels)),
			Namespace: namespace,
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: targetLabels,
			},
			Ingress: []netv1.NetworkPolicyIngressRule{
				{
					From: []netv1.NetworkPolicyPeer{},
				},
			},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
		},
	}
}

// https://github.com/ahmetb/kubernetes-network-policy-recipes/blob/master/06-allow-traffic-from-a-namespace.md
/*
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: web-allow-prod
spec:
  podSelector:
    matchLabels:
      app: web
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          purpose: production
*/
func AllowFromNamespaceTo(namespace string, namespaceLabels, toLabels map[string]string) *netv1.NetworkPolicy {
	return &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("allow-from-namespace-to-%s", LabelString(toLabels)),
			Namespace: namespace,
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: toLabels,
			},
			Ingress: []netv1.NetworkPolicyIngressRule{
				{
					From: []netv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{MatchLabels: namespaceLabels},
						},
					},
				},
			},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
		},
	}
}

// https://github.com/ahmetb/kubernetes-network-policy-recipes/blob/master/11-deny-egress-traffic-from-an-application.md
/*
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: foo-deny-egress
spec:
  podSelector:
    matchLabels:
      app: foo
  policyTypes:
  - Egress
  egress: []
*/
func AllowNoEgressFromLabels(namespace string, targetLabels map[string]string) *netv1.NetworkPolicy {
	return &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("allow-no-egress-from-labels-%s", LabelString(targetLabels)),
			Namespace: namespace,
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: targetLabels,
			},
			Egress:      []netv1.NetworkPolicyEgressRule{},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
		},
	}
}

/*
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:

	name: foo-deny-egress

spec:

	podSelector:
	  matchLabels:
	    app: foo
	policyTypes:
	- Egress
	egress:
	# allow DNS resolution
	- ports:
	  - port: 53
	    protocol: UDP
	  - port: 53
	    protocol: TCP
*/
func AllowEgressOnPort(namespace string, targetLabels map[string]string, port int) *netv1.NetworkPolicy {
	tcp := v1.ProtocolTCP
	udp := v1.ProtocolUDP
	portRef := intstr.FromInt(port)
	return &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("allow-egress-on-port-%s", LabelString(targetLabels)),
			Namespace: namespace,
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: targetLabels,
			},
			Egress: []netv1.NetworkPolicyEgressRule{
				{
					Ports: []netv1.NetworkPolicyPort{
						{Protocol: &tcp, Port: &portRef},
						{Protocol: &udp, Port: &portRef},
					},
				},
			},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
		},
	}
}

// https://github.com/ahmetb/kubernetes-network-policy-recipes/blob/master/12-deny-all-non-whitelisted-traffic-from-the-namespace.md
/*
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: default-deny-all-egress
  Namespace: default
spec:
  policyTypes:
  - Egress
  podSelector: {}
  egress: []
*/
func AllowNoEgressFromNamespace(namespace string) *netv1.NetworkPolicy {
	return &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-no-egress-from-namespace",
			Namespace: namespace,
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			Egress:      []netv1.NetworkPolicyEgressRule{},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
		},
	}
}

// https://github.com/ahmetb/kubernetes-network-policy-recipes/blob/master/14-deny-external-egress-traffic.md
/*
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: foo-deny-external-egress
spec:
  podSelector:
    matchLabels:
      app: foo
  policyTypes:
  - Egress
  egress:
  - ports:
    - port: 53
      protocol: UDP
    - port: 53
      protocol: TCP
    to:
    - namespaceSelector: {}
*/
func AllowEgressToAllNamespacesOnPort(namespace string, targetLabels map[string]string, port int) *netv1.NetworkPolicy {
	tcp := v1.ProtocolTCP
	udp := v1.ProtocolUDP
	portRef := intstr.FromInt(port)
	return &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("allow-egress-to-all-namespace-from-%s-on-port-%d", LabelString(targetLabels), port),
			Namespace: namespace,
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: targetLabels,
			},
			Egress: []netv1.NetworkPolicyEgressRule{
				{
					Ports: []netv1.NetworkPolicyPort{
						{Protocol: &tcp, Port: &portRef},
						{Protocol: &udp, Port: &portRef},
					},
					To: []netv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{},
						},
					},
				},
			},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
		},
	}
}

func AllowNothingToEmptyIngress(namespace string, targetLabels map[string]string) *netv1.NetworkPolicy {
	return &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("allow-nothing-to-v2-%s", LabelString(targetLabels)),
			Namespace: namespace,
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: targetLabels,
			},
			Ingress:     []netv1.NetworkPolicyIngressRule{},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
		},
	}
}

/*
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:

	name: allow-nothing

spec:

	podSelector:
	  matchLabels:
	    app: foo
	policyTypes:
	- Egress
	- Ingress
*/
func AllowNoIngressNorEgress(namespace string, targetLabels map[string]string) *netv1.NetworkPolicy {
	return &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-nothing",
			Namespace: namespace,
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: targetLabels,
			},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress, netv1.PolicyTypeEgress},
		},
	}
}

// https://github.com/ahmetb/kubernetes-network-policy-recipes/blob/master/10-allowing-traffic-with-multiple-selectors.md
/*
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: redis-allow-services
spec:
  podSelector:
    matchLabels:
      app: bookstore
      role: db
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: bookstore
          role: search
    - podSelector:
        matchLabels:
          app: bookstore
          role: api
    - podSelector:
        matchLabels:
          app: inventory
          role: web
*/
func AllowFromMultipleTo(namespace string, fromLabels []map[string]string, targetLabels map[string]string) *netv1.NetworkPolicy {
	fromList := make([]netv1.NetworkPolicyPeer, 0, len(fromLabels))
	for _, labels := range fromLabels {
		fromList = append(fromList, netv1.NetworkPolicyPeer{
			PodSelector: &metav1.LabelSelector{MatchLabels: labels},
		})
	}
	return &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("allow-from-multiple-to-%s", LabelString(targetLabels)),
			Namespace: namespace,
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: targetLabels,
			},
			Ingress: []netv1.NetworkPolicyIngressRule{
				{From: fromList},
			},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
		},
	}
}

func AllowFromMultipleIPBlockTo(namespace string, fromIPBlocks, targetLabels map[string]string) *netv1.NetworkPolicy {
	fromList := make([]netv1.NetworkPolicyPeer, 0, len(fromIPBlocks))
	for ip, excludedIP := range fromIPBlocks {
		netpolPeer := netv1.NetworkPolicyPeer{IPBlock: &netv1.IPBlock{CIDR: ip, Except: []string{excludedIP}}}
		fromList = append(fromList, netpolPeer)
	}
	return &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("allow-from-multiple-ip-blocks-to-%s", LabelString(targetLabels)),
			Namespace: namespace,
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: targetLabels,
			},
			Ingress: []netv1.NetworkPolicyIngressRule{
				{From: fromList},
			},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
		},
	}
}

// https://kubernetes.io/docs/concepts/services-networking/network-policies/#behavior-of-to-and-from-selectors
/*
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          user: alice
      podSelector:
        matchLabels:
          role: client
*/
func AccidentalAnd(namespace string, targetLabels, ingressNamespaceLabels, ingressPodLabels map[string]string) *netv1.NetworkPolicy {
	return &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "accidental-and",
			Namespace: namespace,
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: targetLabels,
			},
			Ingress: []netv1.NetworkPolicyIngressRule{
				{
					From: []netv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: ingressNamespaceLabels,
							},
							PodSelector: &metav1.LabelSelector{
								MatchLabels: ingressPodLabels,
							},
						},
					},
				},
			},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
		},
	}
}

// https://kubernetes.io/docs/concepts/services-networking/network-policies/#behavior-of-to-and-from-selectors
/*
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          user: alice
    - podSelector:
        matchLabels:
          role: client
*/
func AccidentalOr(namespace string, targetLabels, ingressNamespaceLabels, ingressPodLabels map[string]string) *netv1.NetworkPolicy {
	return &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "accidental-or",
			Namespace: namespace,
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: targetLabels,
			},
			Ingress: []netv1.NetworkPolicyIngressRule{
				{
					From: []netv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: ingressNamespaceLabels,
							},
						},
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: ingressPodLabels,
							},
						},
					},
				},
			},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
		},
	}
}

type TestEntry struct {
	name        string
	src         string
	dst         string
	protocol    string
	port        string
	res         bool
	allConnsRes string
	nsList      []*v1.Namespace
	podsList    []*v1.Pod
	policies    []*netv1.NetworkPolicy
}

func initTest(test *TestEntry, t *testing.T) (*PolicyEngine, error) {
	t.Helper()
	pe := NewPolicyEngine()
	if len(test.nsList) > 0 || len(test.podsList) > 0 || len(test.policies) > 0 {
		err := pe.SetResources(test.policies, test.podsList, test.nsList)
		if err != nil {
			t.Fatalf("error init test: %v", err)
			return nil, err
		}
	}
	return pe, nil
}

func checkTestEntry(test *TestEntry, t *testing.T, pe *PolicyEngine) {
	t.Helper()
	res, err := pe.CheckIfAllowed(test.src, test.dst, test.protocol, test.port)
	if err != nil {
		t.Fatalf("test %v: expected err to be nil, but got %v", test.name, err)
	}
	if test.res != res {
		t.Fatalf("test %v: mismatch on test result: expected %v, got %v", test.name, test.res, res)
	}
	res2, err := pe.checkIfAllowedNew(test.src, test.dst, test.protocol, test.port)
	if err != nil {
		t.Fatalf("checkIfAllowedNew, test %v: expected err to be nil, but got %v", test.name, err)
	}
	if test.res != res2 {
		t.Fatalf("checkIfAllowedNew test %v: mismatch on test result: expected %v, got %v", test.name, test.res, res2)
	}
}

func checkTestAllConnectionsEntry(test *TestEntry, t *testing.T, pe *PolicyEngine) {
	t.Helper()
	res, err := pe.allAllowedConnections(test.src, test.dst)
	if err != nil {
		t.Fatalf("test %v: expected err to be nil, but got %v", test.name, err)
	}
	if test.allConnsRes != res.String() {
		t.Fatalf("test %v: mismatch on test result: expected %v, got %v", test.name, test.allConnsRes, res.String())
	}
}

func TestBasic(t *testing.T) {
	var policies []*netv1.NetworkPolicy
	netpol, err := netpolFromYaml(allowAllOnSCTPSerialized)

	if err != nil {
		t.Fatalf("error getting netpol object")
	}
	policies = append(policies, netpol)

	podsList := []*v1.Pod{}
	podsYamlList := []string{podB, podC}
	for _, podYaml := range podsYamlList {
		podObj, err1 := podFromYaml(podYaml)
		if err1 != nil {
			t.Fatalf("error getting pod object")
		}
		podsList = append(podsList, podObj)
	}

	nsList := []*v1.Namespace{}
	nsList = append(nsList, &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default", Labels: map[string]string{"a": "b"}}})

	pe := NewPolicyEngine()
	err = pe.SetResources(policies, podsList, nsList)
	if err != nil {
		t.Fatalf("error SetResources: %v", err)
	}

	testList := []TestEntry{
		{name: "t1", src: "default/b", dst: "192.168.242.0", protocol: "tcp", port: "80", res: true, allConnsRes: "TCP 80,UDP 53"},
		{name: "t2", src: "default/b", dst: "192.169.0.0", protocol: "tcp", port: "80", res: false, allConnsRes: "UDP 53"},
		{name: "t3", src: "default/b", dst: "default/c", protocol: "tcp", port: "80", res: true, allConnsRes: "TCP 80,UDP 53"},
		{name: "t4", src: "default/b", dst: "default/c", protocol: "tcp", port: "81", res: false, allConnsRes: "TCP 80,UDP 53"},
	}

	for i := range testList {
		checkTestEntry(&testList[i], t, pe)
		checkTestAllConnectionsEntry(&testList[i], t, pe)
	}
}

func addNewPod(namespace, name string, labels map[string]string) (*v1.Pod, error) {
	basicPodYaml := podB
	podObj, err := podFromYaml(basicPodYaml)
	if err != nil {
		return nil, err
	}
	podObj.Name = name
	podObj.Namespace = namespace
	podObj.Labels = labels
	return podObj, nil
}

func writeRes(res, fileName string) {
	if err := output.WriteToFile(res, fileName); err != nil {
		fmt.Printf("error writing to file: %v", err)
	}
}

func setResourcesFromDir(pe *PolicyEngine, path string, netpolLimit ...int) error {
	rList, _ := fsscanner.GetResourceInfosFromDirPath([]string{path}, true, false)
	objectsList, processingErrs := parser.ResourceInfoListToK8sObjectsList(rList, logger.NewDefaultLogger(), false)
	if len(processingErrs) > 0 {
		return errors.New("processing errors occurred")
	}
	var netpols = []*netv1.NetworkPolicy{}
	var pods = []*v1.Pod{}
	var ns = []*v1.Namespace{}
	for i := range objectsList {
		obj := objectsList[i]
		switch obj.Kind {
		case "Pod":
			pods = append(pods, obj.Pod)
		case "Namespace":
			ns = append(ns, obj.Namespace)
		case "NetworkPolicy":
			netpols = append(netpols, obj.NetworkPolicy)
		default:
			continue
		}
	}
	if len(netpolLimit) > 0 {
		netpols = netpols[:netpolLimit[0]]
	}
	return pe.SetResources(netpols, pods, ns)
}

//
//gocyclo:ignore
func TestGeneralPerformance(t *testing.T) {
	// Github environment variable is always set to true
	// (https://docs.github.com/en/actions/learn-github-actions/variables#default-environment-variables)
	// skipping this test on github
	if os.Getenv("CI") != "" {
		t.Skip("skipping TestGeneralPerformance")
	}
	path := testutils.GetTestDirPath("onlineboutique")
	// list of connections to test with, for CheckIfAllowed / checkIfAllowedNew
	connectionsListForTest := []TestEntry{
		{protocol: "tcp", port: "5050"},
		{protocol: "tcp", port: "3550"},
		{protocol: "tcp", port: "50051"},
		{protocol: "tcp", port: "7070"},
		{protocol: "tcp", port: "8080"},
		{protocol: "tcp", port: "9555"},
		{protocol: "tcp", port: "7000"},
		{protocol: "udp", port: "7000"},
	}

	// TODO: consider adding caching of non-captured pods when building the network config
	functionNames := []string{"CheckIfAllowed", "CheckIfAllowedNew", "AllAllowedConnections"}
	netpolLimitMin := 0
	netpolLimitMax := 11
	experimentsRepetition := 10
	allResStr := ""
	allResStrPerFunc := map[string]string{"CheckIfAllowed": "", "CheckIfAllowedNew": "", "AllAllowedConnections": ""}
	allResPerFuncAndNetpolLimit := map[int]map[string]string{}
	for i := netpolLimitMin; i <= netpolLimitMax; i++ {
		pe := NewPolicyEngine()

		err := setResourcesFromDir(pe, path, i)
		if err != nil {
			t.Fatalf("error from SetResourcesFromDir")
		}
		allResPerFuncAndNetpolLimit[i] = map[string]string{}
		for _, functionName := range functionNames {
			loopsCounterPerFunction := map[string]int{}
			runTimes := []time.Duration{}
			for j := 0; j < experimentsRepetition; j++ {
				start := time.Now()
				loopsCounter := 0
				for podName1 := range pe.podsMap {
					for podName2 := range pe.podsMap {
						if functionName == "AllAllowedConnections" {
							_, err := pe.allAllowedConnections(podName1, podName2)
							loopsCounter++
							if err != nil {
								t.Fatalf("error from AllAllowedConnections")
							}
						} else {
							for _, conn := range connectionsListForTest {
								if functionName == "CheckIfAllowed" {
									_, err := pe.CheckIfAllowed(podName1, podName2, conn.protocol, conn.port)
									loopsCounter++
									if err != nil {
										t.Fatalf("error from CheckIfAllowed")
									}
								} else {
									_, err := pe.checkIfAllowedNew(podName1, podName2, conn.protocol, conn.port)
									loopsCounter++
									if err != nil {
										t.Fatalf("error from CheckIfAllowed")
									}
								}
							}
						}
					}
				}
				elapsed := time.Since(start)
				loopsCounterPerFunction[functionName] = loopsCounter
				runTimes = append(runTimes, elapsed) // len is experimentsRepetition , each entry is runtime for loopsCounter iterations
			}
			// add a test result line here
			runtimeValues := ""
			lenValues := 0
			sumRuntime := time.Duration(0)
			for _, runtime := range runTimes {
				if float64(runtime) > float64(0.000000000001) {
					sumRuntime += runtime
					runtimeValues += fmt.Sprintf("%v,", runtime)
					lenValues++
				}
			}

			avgRuntime := time.Duration(0)
			if lenValues > 0 {
				avgRuntime = sumRuntime / time.Duration(lenValues)
			}

			// evaluate performance: number of calls per 1 second
			val := int64(avgRuntime) // runtime in nanoseconds
			numCallsPerSec := (int64(loopsCounterPerFunction[functionName]) * 1000000000) / val
			fmt.Printf("%v", numCallsPerSec)
			allResStr += fmt.Sprintf("runtime values: %v\n", runtimeValues)
			allResStr += fmt.Sprintf("function name: %v, netpolLimit: %v, average runtime is %v for %v iterations, numCallsPerSec: %v\n",
				functionName, i, avgRuntime, loopsCounterPerFunction[functionName], numCallsPerSec)
			allResStrPerFunc[functionName] += fmt.Sprintf("%v, %v\n", i, numCallsPerSec)
			allResPerFuncAndNetpolLimit[i][functionName] = fmt.Sprintf("%v", numCallsPerSec)
		}

		pe.ClearResources()
	}
	writeRes(allResStr, "test_all.txt")
	for funcName, res := range allResStrPerFunc {
		writeRes(res, "all_res_"+funcName+".txt")
	}
	resAllFuncNumCallsPerSec := ""
	for n, resMap := range allResPerFuncAndNetpolLimit {
		resAllFuncNumCallsPerSec += fmt.Sprintf("%v  ", n)
		for funcName, res := range resMap {
			resAllFuncNumCallsPerSec += fmt.Sprintf("  %v  %v  ", funcName, res)
		}
		resAllFuncNumCallsPerSec += "\n"
	}
	writeRes(resAllFuncNumCallsPerSec, "all_res_all.txt")
}

func TestFromFiles2(t *testing.T) {
	path := testutils.GetTestDirPath("onlineboutique")
	pe := NewPolicyEngine()
	err := setResourcesFromDir(pe, path)
	if err != nil {
		t.Fatalf("error from SetResourcesFromDir")
	}
	connectionsListForTest := []TestEntry{
		{protocol: "tcp", port: "5050"},
		{protocol: "tcp", port: "3550"},
		{protocol: "tcp", port: "50051"},
		{protocol: "tcp", port: "7070"},
		{protocol: "tcp", port: "8080"},
		{protocol: "tcp", port: "9555"},
		{protocol: "tcp", port: "7000"},
		{protocol: "udp", port: "7000"},
	}

	runTimes := []time.Duration{}
	experiments := 10

	allResStr := ""
	for i := 0; i < experiments; i++ {
		start := time.Now()
		for podName1 := range pe.podsMap {
			for podName2 := range pe.podsMap {
				for _, conn := range connectionsListForTest {
					if i < 5 {
						_, err := pe.CheckIfAllowed(podName1, podName2, conn.protocol, conn.port)
						if err != nil {
							t.Fatalf("error from CheckIfAllowed")
						}
					} else {
						_, err := pe.checkIfAllowedNew(podName1, podName2, conn.protocol, conn.port)
						if err != nil {
							t.Fatalf("error from CheckIfAllowed")
						}
					}
					/*// resStr := fmt.Sprintf("%v, %v, %v, %v, %v\n", podName1, podName2, conn.protocol, conn.port, res)
					// allResStr += resStr*/
				}
			}
		}
		elapsed := time.Since(start)
		runTimes = append(runTimes, elapsed)
	}
	for i, runtime := range runTimes {
		allResStr += fmt.Sprintf("%v, %s\n", i, runtime)
	}
	/*// allResStr += fmt.Sprintf("total runtime: %s\n", elapsed)*/
	writeRes(allResStr, "test_check_if_allowed_func.txt")
}

func TestFromFiles(t *testing.T) {
	path := testutils.GetTestDirPath("onlineboutique")
	pe := NewPolicyEngine()
	err := setResourcesFromDir(pe, path)
	if err != nil {
		t.Fatalf("error from SetResourcesFromDir")
	}
	res, err := pe.allAllowedConnections("default/frontend-99684f7f8-l7mqq", "default/adservice-77d5cd745d-t8mx4")
	if err != nil {
		t.Fatalf("error from AllAllowedConnectionSet")
	}
	fmt.Printf("%v", res)
	runTimes := []time.Duration{}
	experiments := 10
	allResStr := ""
	for i := 0; i < experiments; i++ {
		start := time.Now()
		/*// allResStr := ""*/
		for podName1 := range pe.podsMap {
			for podName2 := range pe.podsMap {
				_, err := pe.allAllowedConnections(podName1, podName2)
				if err != nil {
					t.Fatalf("error from AllAllowedConnections")
				}
				/*// resStr := fmt.Sprintf("%v, %v, %v,  time: %s\n", podName1, podName2, res.String(), elapsed)
				// resStr := fmt.Sprintf("%v, %v, %v\n", podName1, podName2, res.String())
				// writeRes(resStr)
				// allResStr += resStr
				// fmt.Printf("%v, %v, %v", podName1, podName2, res.String())*/
			}
		}
		elapsed := time.Since(start)
		runTimes = append(runTimes, elapsed)
	}
	for i, runtime := range runTimes {
		allResStr += fmt.Sprintf("%v, %s\n", i, runtime)
	}
	writeRes(allResStr, "test_all_allowed_conns_func.txt")
}

func TestNew(t *testing.T) {
	var AllExamples = map[string][]*netv1.NetworkPolicy{
		"AllowNothingTo":      {AllowNothingTo("default", map[string]string{"app": "web"})},
		"AllowAllTo":          {AllowAllTo("default", map[string]string{"app": "web"})},
		"AllowSpecificPortTo": {AllowSpecificPortTo("default", label("role", "monitoring"), label("app", "apiserver"), 5000)},
		"AllowAllTo_Version2": {AllowAllToVersion2("default", label("app", "web"))},
		"AllowFromDifferentNamespaceWithLabelsTo": {AllowFromDifferentNamespaceWithLabelsTo("default",
			label("type", "monitoring"), label("team", "operations"), label("app", "web"))},
		"AllowAllWithinNamespace": {AllowAllWithinNamespace("default")},
		"AllowAllTo_Version3":     {AllowAllToVersion3("default", label("app", "web"))},
		"AllowAllTo_Version4":     {AllowAllToVersion4("default", label("app", "web"))},
		"AllowNothingToAnything":  {AllowNothingToAnything("default")},
		"AllowFromTo": {AllowFromTo("default", map[string]string{"app": "apiserver"},
			map[string]string{"app": "web"})},
		"AllowFromAnywhere":                {AllowFromAnywhere("default", label("app", "web"))},
		"AllowFromNamespaceTo":             {AllowFromNamespaceTo("default", label("team", "operations"), label("app", "web"))},
		"AllowNoEgressFromLabels":          {AllowNoEgressFromLabels("default", label("app", "web"))},
		"AllowEgressOnPort":                {AllowEgressOnPort("default", label("app", "web"), 53)},
		"AllowNoEgressFromNamespace":       {AllowNoEgressFromNamespace("default")},
		"AllowEgressToAllNamespacesOnPort": {AllowEgressToAllNamespacesOnPort("default", label("app", "web"), 53)},
		"AllowNothingToEmptyIngress":       {AllowNothingToEmptyIngress("default", label("app", "web"))},
		"AllowNoIngressNorEgress":          {AllowNoIngressNorEgress("default", label("app", "web"))},
		"AllowFromMultipleTo": {AllowFromMultipleTo(
			"default",
			[]map[string]string{
				{"app": "bookstore", "role": "search"},
				{"app": "bookstore", "role": "api"},
				{"app": "inventory", "role": "web"},
			},
			map[string]string{"app": "bookstore", "role": "db"})},
		"AccidentalAnd": {AccidentalAnd("default", label("app", "web"), label("team", "operations"), label("type", "monitoring"))},
		"AccidentalOr":  {AccidentalOr("default", label("app", "web"), label("team", "operations"), label("role", "search"))},
		"AllowFromMultipleIpBlockTo": {AllowFromMultipleIPBlockTo("default",
			map[string]string{"172.17.0.0/16": "172.17.0.0/24", "10.0.0.0/16": "10.0.0.0/24"},
			label("app", "web"))},
	}

	podsList := []*v1.Pod{}
	podsYamlList := []string{podB, podC, podD}
	for _, podYaml := range podsYamlList {
		podObj, err := podFromYaml(podYaml)
		if err != nil {
			t.Fatalf("error getting pod object")
		}
		podsList = append(podsList, podObj)
	}
	// additional pods added here
	podE, err := addNewPod("default", "e", map[string]string{"app": "bookstore", "role": "search"})
	if err != nil {
		t.Fatalf("error getting pod object")
	}
	podF, err := addNewPod("default", "f", map[string]string{"app": "bookstore", "role": "api"})
	if err != nil {
		t.Fatalf("error getting pod object")
	}
	podG, err := addNewPod("default", "g", map[string]string{"app": "inventory", "role": "web"})
	if err != nil {
		t.Fatalf("error getting pod object")
	}
	podH, err := addNewPod("default", "h", map[string]string{"app": "bookstore", "role": "db"})
	if err != nil {
		t.Fatalf("error getting pod object")
	}
	podJ, err := addNewPod("operations", "j", map[string]string{"app": "bookstore1", "role": "db1"})
	if err != nil {
		t.Fatalf("error getting pod object")
	}
	podsList = append(podsList, []*v1.Pod{podE, podF, podG, podH, podJ}...)

	nsList := []*v1.Namespace{
		{ObjectMeta: metav1.ObjectMeta{Name: "default", Labels: map[string]string{"a": "b"}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "operations", Labels: map[string]string{"team": "operations"}}},
	}

	testList := []TestEntry{
		{name: "t1", nsList: nsList, podsList: podsList, policies: AllExamples["AllowNothingTo"], src: "default/c",
			dst: "default/b", protocol: "tcp", port: "80", res: false, allConnsRes: "No Connections"},
		{name: "t2", nsList: nsList, podsList: podsList, policies: AllExamples["AllowAllTo"], src: "default/c",
			dst: "default/b", protocol: "tcp", port: "80", res: true, allConnsRes: "All Connections"},
		{name: "t3", nsList: nsList, podsList: podsList, policies: append(AllExamples["AllowNothingTo"],
			AllExamples["AllowAllTo"]...), src: "default/c",
			dst: "default/b", protocol: "tcp", port: "80", res: true, allConnsRes: "All Connections"},
		{name: "t4", nsList: nsList, podsList: podsList, policies: AllExamples["AllowSpecificPortTo"], src: "default/b",
			dst: "default/c", protocol: "tcp", port: "5000", res: true, allConnsRes: "TCP 5000"},
		{name: "t5", nsList: nsList, podsList: podsList, policies: AllExamples["AllowAllTo_Version2"], src: "default/c",
			dst: "default/b", protocol: "tcp", port: "80", res: true, allConnsRes: "All Connections"},
		{name: "t6", nsList: nsList, podsList: podsList, policies: AllExamples["AllowFromDifferentNamespaceWithLabelsTo"], src: "operations/d",
			dst: "default/b", protocol: "tcp", port: "80", res: true, allConnsRes: "All Connections"},
		{name: "t7", nsList: nsList, podsList: podsList, policies: AllExamples["AllowFromDifferentNamespaceWithLabelsTo"], src: "default/c",
			dst: "default/b", protocol: "tcp", port: "80", res: false, allConnsRes: "No Connections"},
		{name: "t8", nsList: nsList, podsList: podsList, policies: AllExamples["AllowAllWithinNamespace"], src: "default/c",
			dst: "default/b", protocol: "tcp", port: "80", res: true, allConnsRes: "All Connections"},
		{name: "t9", nsList: nsList, podsList: podsList, policies: AllExamples["AllowAllWithinNamespace"], src: "default/b",
			dst: "default/c", protocol: "tcp", port: "80", res: true, allConnsRes: "All Connections"},
		{name: "t10", nsList: nsList, podsList: podsList, policies: AllExamples["AllowAllWithinNamespace"], src: "operations/d",
			dst: "default/c", protocol: "tcp", port: "80", res: false, allConnsRes: "No Connections"},
		{name: "t11", nsList: nsList, podsList: podsList, policies: AllExamples["AllowAllTo_Version3"], src: "default/c",
			dst: "default/b", protocol: "tcp", port: "80", res: true, allConnsRes: "All Connections"},
		{name: "t12", nsList: nsList, podsList: podsList, policies: AllExamples["AllowAllTo_Version3"], src: "operations/d",
			dst: "default/b", protocol: "tcp", port: "80", res: true, allConnsRes: "All Connections"},
		{name: "t13", nsList: nsList, podsList: podsList, policies: AllExamples["AllowAllTo_Version4"], src: "default/c",
			dst: "default/b", protocol: "tcp", port: "80", res: true, allConnsRes: "All Connections"},
		{name: "t14", nsList: nsList, podsList: podsList, policies: AllExamples["AllowAllTo_Version4"], src: "operations/d",
			dst: "default/b", protocol: "tcp", port: "80", res: true, allConnsRes: "All Connections"},
		{name: "t15", nsList: nsList, podsList: podsList, policies: AllExamples["AllowNothingToAnything"], src: "default/c",
			dst: "default/b", protocol: "tcp", port: "80", res: false, allConnsRes: "No Connections"},
		{name: "t16", nsList: nsList, podsList: podsList, policies: AllExamples["AllowNothingToAnything"], src: "default/b",
			dst: "default/c", protocol: "tcp", port: "80", res: false, allConnsRes: "No Connections"},
		{name: "t17", nsList: nsList, podsList: podsList, policies: AllExamples["AllowNothingToAnything"], src: "operations/d",
			dst: "default/c", protocol: "tcp", port: "80", res: false, allConnsRes: "No Connections"},
		{name: "t18", nsList: nsList, podsList: podsList, policies: AllExamples["AllowNothingToAnything"], src: "default/b",
			dst: "operations/d", protocol: "tcp", port: "80", res: true, allConnsRes: "All Connections"},
		{name: "t19", nsList: nsList, podsList: podsList, policies: AllExamples["AllowFromTo"], src: "default/c",
			dst: "default/b", protocol: "tcp", port: "80", res: true, allConnsRes: "All Connections"},
		{name: "t20", nsList: nsList, podsList: podsList, policies: AllExamples["AllowFromTo"], src: "operations/d",
			dst: "default/b", protocol: "tcp", port: "80", res: false, allConnsRes: "No Connections"},
		{name: "t21", nsList: nsList, podsList: podsList, policies: AllExamples["AllowFromAnywhere"], src: "default/c",
			dst: "default/b", protocol: "tcp", port: "80", res: true, allConnsRes: "All Connections"},
		{name: "t22", nsList: nsList, podsList: podsList, policies: AllExamples["AllowFromAnywhere"], src: "192.168.242.0",
			dst: "default/b", protocol: "tcp", port: "80", res: true, allConnsRes: "All Connections"},
		{name: "t23", nsList: nsList, podsList: podsList, policies: AllExamples["AllowFromAnywhere"], src: "operations/d",
			dst: "default/b", protocol: "tcp", port: "80", res: true, allConnsRes: "All Connections"},
		{name: "t24", nsList: nsList, podsList: podsList, policies: AllExamples["AllowFromNamespaceTo"], src: "operations/d",
			dst: "default/b", protocol: "tcp", port: "80", res: true, allConnsRes: "All Connections"},
		{name: "t25", nsList: nsList, podsList: podsList, policies: AllExamples["AllowFromNamespaceTo"], src: "default/c",
			dst: "default/b", protocol: "tcp", port: "80", res: false, allConnsRes: "No Connections"},
		{name: "t26", nsList: nsList, podsList: podsList, policies: AllExamples["AllowNoEgressFromLabels"], src: "default/b",
			dst: "default/c", protocol: "tcp", port: "80", res: false, allConnsRes: "No Connections"},
		{name: "t27", nsList: nsList, podsList: podsList, policies: AllExamples["AllowNoEgressFromLabels"], src: "default/c",
			dst: "default/b", protocol: "tcp", port: "80", res: true, allConnsRes: "All Connections"},
		{name: "t28", nsList: nsList, podsList: podsList, policies: AllExamples["AllowEgressOnPort"], src: "default/b",
			dst: "default/c", protocol: "tcp", port: "53", res: true, allConnsRes: "TCP 53,UDP 53"},
		{name: "t29", nsList: nsList, podsList: podsList, policies: AllExamples["AllowEgressOnPort"], src: "default/c",
			dst: "default/b", protocol: "tcp", port: "80", res: true, allConnsRes: "All Connections"},
		{name: "t30", nsList: nsList, podsList: podsList, policies: AllExamples["AllowNoEgressFromNamespace"], src: "default/c",
			dst: "default/b", protocol: "tcp", port: "80", res: false, allConnsRes: "No Connections"},
		{name: "t31", nsList: nsList, podsList: podsList, policies: AllExamples["AllowNoEgressFromNamespace"], src: "default/b",
			dst: "default/c", protocol: "tcp", port: "80", res: false, allConnsRes: "No Connections"},
		{name: "t32", nsList: nsList, podsList: podsList, policies: AllExamples["AllowNoEgressFromNamespace"], src: "operations/d",
			dst: "default/c", protocol: "tcp", port: "80", res: true, allConnsRes: "All Connections"},
		{name: "t33", nsList: nsList, podsList: podsList, policies: AllExamples["AllowEgressToAllNamespacesOnPort"], src: "default/b",
			dst: "default/c", protocol: "tcp", port: "53", res: true, allConnsRes: "TCP 53,UDP 53"},
		{name: "t34", nsList: nsList, podsList: podsList, policies: AllExamples["AllowEgressToAllNamespacesOnPort"], src: "default/b",
			dst: "operations/d", protocol: "tcp", port: "53", res: true, allConnsRes: "TCP 53,UDP 53"},
		{name: "t35", nsList: nsList, podsList: podsList, policies: AllExamples["AllowEgressToAllNamespacesOnPort"], src: "default/b",
			dst: "192.168.242.0", protocol: "tcp", port: "53", res: false, allConnsRes: "No Connections"},
		{name: "t36", nsList: nsList, podsList: podsList, policies: AllExamples["AllowEgressToAllNamespacesOnPort"], src: "default/c",
			dst: "default/b", protocol: "tcp", port: "80", res: true, allConnsRes: "All Connections"},
		{name: "t37", nsList: nsList, podsList: podsList, policies: AllExamples["AllowNothingToEmptyIngress"], src: "default/c",
			dst: "default/b", protocol: "tcp", port: "80", res: false, allConnsRes: "No Connections"},
		{name: "t38", nsList: nsList, podsList: podsList, policies: AllExamples["AllowNothingToEmptyIngress"], src: "default/b",
			dst: "default/c", protocol: "tcp", port: "80", res: true, allConnsRes: "All Connections"},
		{name: "t39", nsList: nsList, podsList: podsList, policies: AllExamples["AllowNoIngressNorEgress"], src: "default/c",
			dst: "default/b", protocol: "tcp", port: "80", res: false, allConnsRes: "No Connections"},
		{name: "t40", nsList: nsList, podsList: podsList, policies: AllExamples["AllowNoIngressNorEgress"], src: "default/b",
			dst: "default/c", protocol: "tcp", port: "80", res: false, allConnsRes: "No Connections"},
		{name: "t41", nsList: nsList, podsList: podsList, policies: AllExamples["AllowNoIngressNorEgress"], src: "default/c",
			dst: "operations/d", protocol: "tcp", port: "80", res: true, allConnsRes: "All Connections"},
		{name: "t42", nsList: nsList, podsList: podsList, policies: AllExamples["AllowNoIngressNorEgress"], src: "operations/d",
			dst: "default/c", protocol: "tcp", port: "80", res: true, allConnsRes: "All Connections"},
		{name: "t43", nsList: nsList, podsList: podsList, policies: AllExamples["AllowFromMultipleTo"], src: "default/e",
			dst: "default/h", protocol: "tcp", port: "80", res: true, allConnsRes: "All Connections"},
		{name: "t44", nsList: nsList, podsList: podsList, policies: AllExamples["AllowFromMultipleTo"], src: "default/f",
			dst: "default/h", protocol: "tcp", port: "80", res: true, allConnsRes: "All Connections"},
		{name: "t45", nsList: nsList, podsList: podsList, policies: AllExamples["AllowFromMultipleTo"], src: "default/g",
			dst: "default/h", protocol: "tcp", port: "80", res: true, allConnsRes: "All Connections"},
		{name: "t46", nsList: nsList, podsList: podsList, policies: AllExamples["AllowFromMultipleTo"], src: "default/c",
			dst: "default/h", protocol: "tcp", port: "80", res: false, allConnsRes: "No Connections"},
		{name: "t47", nsList: nsList, podsList: podsList, policies: AllExamples["AllowFromMultipleTo"], src: "default/b",
			dst: "default/h", protocol: "tcp", port: "80", res: false, allConnsRes: "No Connections"},
		{name: "t48", nsList: nsList, podsList: podsList, policies: AllExamples["AccidentalAnd"], src: "operations/d",
			dst: "default/b", protocol: "tcp", port: "80", res: true, allConnsRes: "All Connections"},
		{name: "t49", nsList: nsList, podsList: podsList, policies: AllExamples["AccidentalAnd"], src: "default/c",
			dst: "default/b", protocol: "tcp", port: "80", res: false, allConnsRes: "No Connections"},
		{name: "t50", nsList: nsList, podsList: podsList, policies: AllExamples["AccidentalOr"], src: "operations/d",
			dst: "default/b", protocol: "tcp", port: "80", res: true, allConnsRes: "All Connections"},
		{name: "t51", nsList: nsList, podsList: podsList, policies: AllExamples["AccidentalOr"], src: "default/c",
			dst: "default/b", protocol: "tcp", port: "80", res: false, allConnsRes: "No Connections"},
		{name: "t52", nsList: nsList, podsList: podsList, policies: AllExamples["AccidentalOr"], src: "default/e",
			dst: "default/b", protocol: "tcp", port: "80", res: true, allConnsRes: "All Connections"},
		{name: "t53", nsList: nsList, podsList: podsList, policies: AllExamples["AllowFromMultipleIpBlockTo"], src: "172.17.1.0",
			dst: "default/b", protocol: "tcp", port: "80", res: true, allConnsRes: "All Connections"},
		{name: "t54", nsList: nsList, podsList: podsList, policies: AllExamples["AllowFromMultipleIpBlockTo"], src: "10.0.1.0",
			dst: "default/b", protocol: "tcp", port: "80", res: true, allConnsRes: "All Connections"},
		{name: "t55", nsList: nsList, podsList: podsList, policies: AllExamples["AllowFromMultipleIpBlockTo"], src: "172.17.0.0",
			dst: "default/b", protocol: "tcp", port: "80", res: false, allConnsRes: "No Connections"},
		{name: "t56", nsList: nsList, podsList: podsList, policies: AllExamples["AllowFromMultipleIpBlockTo"], src: "10.0.0.0",
			dst: "default/b", protocol: "tcp", port: "80", res: false, allConnsRes: "No Connections"},
		{name: "t57", nsList: nsList, podsList: podsList, policies: AllExamples["AllowFromMultipleIpBlockTo"], src: "11.0.0.0",
			dst: "default/b", protocol: "tcp", port: "80", res: false, allConnsRes: "No Connections"},
		{name: "t58", nsList: nsList, podsList: podsList, policies: AllExamples["AllowFromMultipleIpBlockTo"], src: "default/c",
			dst: "default/b", protocol: "tcp", port: "80", res: false, allConnsRes: "No Connections"},
	}

	for i := range testList {
		pe, err := initTest(&testList[i], t)
		if err != nil {
			t.Fatal(err)
		}
		checkTestEntry(&testList[i], t, pe)
		checkTestAllConnectionsEntry(&testList[i], t, pe)
		pe.ClearResources()
	}
}

/*
// canonical Pod name
func namespacedName(pod *v1.Pod) string {
	return pod.Namespace + "/" + pod.Name
}

func connectivityMap(pe *PolicyEngine, podsList []*v1.Pod, nsList []*v1.Namespace, netpolList []*netv1.NetworkPolicy) ([]string, error) {
	report := []string{}
	err := pe.SetResources(netpolList, podsList, nsList)
	if err != nil {
		return report, err
	}
	for i := range podsList {
		for j := range podsList {
			src := namespacedName(podsList[i])
			dst := namespacedName(podsList[j])
			allowedConnections, err := pe.AllAllowedConnections(src, dst)
			if err == nil {
				reportLine := fmt.Sprintf("src: %v, dest: %v, allowed conns: %v", src, dst, allowedConnections.String())
				report = append(report, reportLine)
			}
		}
	}
	return report, nil
}

func TestConnectivityMap(t *testing.T) {
	currentDir, _ := os.Getwd()
	path := filepath.Join(currentDir, "testdata")
	netpols, pods, ns, err := getResourcesFromDir(path)
	if err != nil {
		return
	}
	pe := NewPolicyEngine()
	res, err := connectivityMap(pe, pods, ns, netpols)
	if err != nil {
		fmt.Printf("%v", err)
		return
	}
	for i := range res {
		fmt.Printf("%v", res[i])
	}
}
*/

func computeExpectedCacheHits(pe *PolicyEngine) (int, error) {
	allPodsCount := len(pe.podsMap)
	podOwnersMap := map[string]int{}

	// count how many pods with common owner and same variant
	for _, pod := range pe.podsMap {
		podOwnerStr := pod.Owner.Name + string(types.Separator) + pod.Owner.Variant
		podOwnersMap[podOwnerStr] += 1
	}
	res := 0
	countSets := 0
	for _, lenMultiplePodsPerDistinctOwner := range podOwnersMap {
		if lenMultiplePodsPerDistinctOwner == 1 {
			continue
		}
		countSets += 1
		// currently assuming only one set of pods with common owner workload to simplify computation
		if countSets > 1 {
			return 0, errors.New("unsupported config for cache hits computation")
		}
		x := allPodsCount
		y := lenMultiplePodsPerDistinctOwner
		// computation: per each pod of such set, starting the second one, count all its pairs with pods without such owner
		// additionally, add for each pod of such set, all its pairs with other pods with such owner, and remove only the first
		// one that should be cached initially
		cacheHits := (y-1)*2*(x-y) + y*(y-1) - 1
		res += cacheHits
	}
	return res, nil
}

func TestCacheWithPodDeletion(t *testing.T) {
	pe := NewPolicyEngine()
	var err error
	testDir := testutils.GetTestDirPath("onlineboutique_with_replicas")
	if err = setResourcesFromDir(pe, testDir); err != nil {
		t.Fatal(err)
	}
	_, err = simpleConfigurableConnectivityMapTest(pe, false, "tcp", "80")
	if err != nil {
		t.Fatal(err)
	}
	countLoadGeneratorDeletion := 0
	cacheKeysCount := len(pe.cache.cache.Keys())
	// delete some pods, until its owner has no pods
	for podName, podObj := range pe.podsMap {
		if strings.Contains(podName, "loadgenerator") {
			v1Pod := &v1.Pod{}
			v1Pod.Name = podObj.Name
			v1Pod.Namespace = podObj.Namespace
			if err = pe.deletePod(v1Pod); err != nil {
				t.Fatal(err)
			}
			countLoadGeneratorDeletion += 1
		}
		// check that relevant cache entries are deleted.
		cacheKeysCountAfterDelete := len(pe.cache.cache.Keys())
		if countLoadGeneratorDeletion < 3 && cacheKeysCountAfterDelete != cacheKeysCount {
			t.Fatalf("unexpected cacheKeysCountAfterDelete : %v before deleting all loadgenerator pods", cacheKeysCountAfterDelete)
		} else if countLoadGeneratorDeletion == 3 && cacheKeysCountAfterDelete >= cacheKeysCount {
			t.Fatalf("unexpected cacheKeysCountAfterDelete : %v after deleting all loadgenerator pods", cacheKeysCountAfterDelete)
		}
	}
}

func TestConnectionsMapExamples(t *testing.T) {
	tests := []struct {
		testName           string
		resourcesDir       string
		expectedOutputFile string
		expectedCacheHits  int
		checkCacheHits     bool
		allConnections     bool
		port               string
		protocol           string
	}{
		// tests with AllAllowedConnections -----------------------------------------------------------------------
		{
			testName:           "onlineboutique_all_allowed_connections",
			resourcesDir:       testutils.GetTestDirPath("onlineboutique"),
			expectedOutputFile: testutils.GetTestDirPath(filepath.Join("onlineboutique", "connections_map_output.txt")),
			// expectedCacheHits:     0, // no pod replicas on this example,
			checkCacheHits: false, // currently not relevant for "all connections" computation( only for bool result is connection allowed )
			allConnections: true,
		},

		// tests with IsConnectionAllowed -----------------------------------------------------------------------------
		{
			testName:           "onlineboutique_bool_connectivity_results",
			resourcesDir:       testutils.GetTestDirPath("onlineboutique"),
			expectedOutputFile: testutils.GetTestDirPath(filepath.Join("onlineboutique", "connections_map_output_bool.txt")),
			//expectedCacheHits:  0, // no pod replicas on this example,
			checkCacheHits: true,
			allConnections: false,
		},

		{
			testName:           "onlineboutique_with_replicas_bool_connectivity_results",
			resourcesDir:       testutils.GetTestDirPath("onlineboutique_with_replicas"),
			expectedOutputFile: testutils.GetTestDirPath(filepath.Join("onlineboutique_with_replicas", "connections_map_with_replicas_output.txt")),
			checkCacheHits:     true,
			allConnections:     false,
			port:               "80",
			protocol:           "TCP",
			//expectedCacheHits:  49, // loadgenerator pod has 3 replicas
		},

		{
			testName:     "onlineboutique_with_replicas_and_variants_bool_connectivity_results",
			resourcesDir: testutils.GetTestDirPath("onlineboutique_with_replicas_and_variants"),
			expectedOutputFile: testutils.GetTestDirPath(filepath.Join("onlineboutique_with_replicas_and_variants",
				"connections_map_with_replicas_and_variants_output.txt")),
			checkCacheHits: true,
			allConnections: false,
			port:           "80",
			protocol:       "TCP",
			//expectedCacheHits: 25, // loadgenerator pod has 3 replicas but one with variant on labels
		},
	}
	for _, test := range tests {
		pe := NewPolicyEngine()
		var err error
		if err = setResourcesFromDir(pe, test.resourcesDir); err != nil {
			t.Fatal(err)
		}

		test.expectedCacheHits, err = computeExpectedCacheHits(pe)
		if err != nil {
			t.Fatal(err)
		}

		res, err := simpleConfigurableConnectivityMapTest(pe, test.allConnections, test.protocol, test.port)
		if err != nil {
			t.Fatal(err)
		}
		if test.checkCacheHits && test.expectedCacheHits != pe.cache.cacheHitsCount {
			t.Fatalf("Test %v: mismatch on expected num of cache hits: expected %v, got %v",
				test.testName, test.expectedCacheHits, pe.cache.cacheHitsCount)
		}

		comparisonRes, err := testConnectivityMapOutput(res, test.expectedOutputFile)
		if err != nil {
			t.Fatal(err)
		}
		if !comparisonRes {
			t.Fatalf("Test %v:mismatch for expected output on connections map test: expected output at %v",
				test.testName, test.expectedOutputFile)
		}
	}
}

func connectionsString(pe *PolicyEngine, srcPod, dstPod, protocol, port string, allConnections bool) (string, error) {
	var allowedConnectionsStr string
	var err error
	if allConnections {
		var allowedConnections *common.ConnectionSet
		allowedConnections, err = pe.allAllowedConnections(srcPod, dstPod)
		if err == nil {
			allowedConnectionsStr = allowedConnections.String()
		}
	} else {
		var allowedConnections bool
		allowedConnections, err = pe.CheckIfAllowed(srcPod, dstPod, protocol, port)
		allowedConnectionsStr = fmt.Sprintf("%v", allowedConnections)
	}
	return allowedConnectionsStr, err
}

func simpleConfigurableConnectivityMapTest(
	pe *PolicyEngine,
	allConnections bool,
	protocol,
	port string) ([]string, error) {
	report := []string{}
	for srcPod := range pe.podsMap {
		for dstPod := range pe.podsMap {
			allowedConnectionsStr, err := connectionsString(pe, srcPod, dstPod, protocol, port, allConnections)
			if err == nil {
				reportLine := fmt.Sprintf("src: %v, dest: %v, allowed conns: %v\n", srcPod, dstPod, allowedConnectionsStr)
				report = append(report, reportLine)
			} else {
				return []string{}, err
			}
		}
	}
	sort.Strings(report)
	return report, nil
}

func testConnectivityMapOutput(res []string, expectedFileName string) (bool, error) {
	outputRes := strings.ReplaceAll(strings.Join(res, ""), "\r", "")
	expectedBytes, err := os.ReadFile(expectedFileName)
	if err != nil {
		return false, err
	}
	expectedStr := strings.ReplaceAll(string(expectedBytes), "\r", "")
	return expectedStr == outputRes, nil
}

func TestDisjointIpBlocks(t *testing.T) {
	path := testutils.GetTestDirPath("ipblockstest")
	pe := NewPolicyEngine()
	if err := setResourcesFromDir(pe, path); err != nil {
		t.Errorf("%v", err)
	}

	_, _, ipList, err := pe.getDisjointIPBlocks()
	if err != nil {
		t.Fatalf("unexpected err getDisjointIPBlocks: %v", err)
	}
	ipStrList := []string{}
	for i := range ipList {
		ipStrList = append(ipStrList, ipList[i].ToIPRanges())
	}
	sort.Strings(ipStrList)
	res := fmt.Sprintf("%v", ipStrList)
	fmt.Printf("ipStrList: %v\n", res)
	ipAddressesExpected := []string{
		"0.0.0.0-9.255.255.255",
		"10.0.0.0-10.255.255.255",
		"11.0.0.0-172.20.255.255",
		"172.21.0.0-172.21.255.255",
		"172.22.0.0-172.29.255.255",
		"172.30.0.0-172.30.255.255",
		"172.31.0.0-255.255.255.255",
	}
	expectedOutput := fmt.Sprintf("%v", ipAddressesExpected)
	if res != expectedOutput {
		t.Fatalf("unexpected output for getDisjointIPBlocks")
	}
}

func TestPolicyEngineWithWorkloads(t *testing.T) {
	path := testutils.GetTestDirPath("onlineboutique_workloads")

	rList, _ := fsscanner.GetResourceInfosFromDirPath([]string{path}, true, false)
	objects, processingErrs := parser.ResourceInfoListToK8sObjectsList(rList, logger.NewDefaultLogger(), false)
	if len(processingErrs) > 0 {
		t.Fatalf("TestPolicyEngineWithWorkloads errors: %v", processingErrs)
	}
	pe, err := NewPolicyEngineWithOptionsList(WithObjectsList(objects))
	if err != nil {
		t.Fatalf("TestPolicyEngineWithWorkloads error: %v", err)
	}
	// 12 deployments, one with 3 replicas, thus expecting 13 pods in policy engine
	if len(pe.podsMap) != 13 {
		t.Fatalf("TestPolicyEngineWithWorkloads: unexpected podsMap len: %d ", len(pe.podsMap))
	}
}

const defaultPort = "80"

func pickContainedConn(conn *common.ConnectionSet) (resProtocol, resPort string) {
	if conn.IsEmpty() {
		return "", ""
	}
	if conn.AllowAll {
		return string(v1.ProtocolTCP), defaultPort
	}
	for protocol, portSet := range conn.AllowedProtocols {
		if portSet.IsEmpty() { // at least in some protocol, portSet will not be empty
			continue
		}
		resProtocol = string(protocol)
		if portSet.IsAll() {
			resPort = defaultPort
		} else {
			resPort = fmt.Sprintf("%d", portSet.Ports.Min())
		}
		break
	}
	return resProtocol, resPort
}

func pickUncontainedConn(conn *common.ConnectionSet) (resProtocol, resPort string) {
	complementSet := common.MakeConnectionSet(true)
	complementSet.Subtract(conn)
	return pickContainedConn(complementSet)
}

func runParsedResourcesEvalTests(t *testing.T, testList []examples.ParsedResourcesTest) {
	t.Helper()
	for i := 0; i < len(testList); i++ {
		test := &testList[i]
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			pe, err := NewPolicyEngineWithOptionsList(WithObjectsList(test.GetK8sObjects()))
			require.Nil(t, err, test.TestInfo)
			for _, evalTest := range test.EvalTests {
				src := evalTest.Src
				dst := evalTest.Dst
				allowedConns, err := pe.allAllowedConnections(src, dst)
				require.Nil(t, err, test.TestInfo)
				require.Equal(t, evalTest.ExpResult, allowedConns.String())

				contProtocol, contPort := pickContainedConn(allowedConns)
				if contPort != "" {
					var res bool
					res, err := pe.CheckIfAllowed(src, dst, contProtocol, contPort)
					require.Nil(t, err, test.TestInfo)
					require.Equal(t, true, res, test.TestInfo)
					res, err = pe.checkIfAllowedNew(src, dst, contProtocol, contPort)
					require.Nil(t, err, test.TestInfo)
					require.Equal(t, true, res, test.TestInfo)
				}
				uncontProtocol, uncontPort := pickUncontainedConn(allowedConns)
				if uncontPort != "" {
					var res bool
					res, err := pe.CheckIfAllowed(src, dst, uncontProtocol, uncontPort)
					require.Nil(t, err, test.TestInfo)
					require.Equal(t, false, res, test.TestInfo)
					res, err = pe.checkIfAllowedNew(src, dst, uncontProtocol, uncontPort)
					require.Nil(t, err, test.TestInfo)
					require.Equal(t, false, res, test.TestInfo)
				}
			}
		})
	}
}

func TestAllParsedResourcesEvalTests(t *testing.T) {
	runParsedResourcesEvalTests(t, examples.ANPConnectivityFromParsedResourcesTest)
	runParsedResourcesEvalTests(t, examples.BANPConnectivityFromParsedResourcesTest)
	runParsedResourcesEvalTests(t, examples.ANPWithNetPolV1FromParsedResourcesTest)
	runParsedResourcesEvalTests(t, examples.BANPWithNetPolV1FromParsedResourcesTest)
	runParsedResourcesEvalTests(t, examples.ANPWithBANPFromParsedResourcesTest)
}

// TestDirPathEvalResults tests eval results of an allowed connection between two peers in the given dir.
// note that: that for some tests, the directory may contain workload resources (not pod resources), then eval result will be
// between src pod and dst pod with pod names owned by these workloads (pods which are added by policy engine ).
func TestDirPathEvalResults(t *testing.T) {
	cases := []struct {
		dir            string
		sourceWorkload string
		sourceNs       string
		destNs         string
		destWorkload   string
		protocol       string
		port           string
		evalResult     bool
	}{
		{
			dir:            "anp_demo",
			sourceNs:       "gryffindor",
			sourceWorkload: "harry-potter",
			destWorkload:   "luna-lovegood",
			destNs:         "ravenclaw",
			protocol:       "udp",
			port:           "52",
			evalResult:     true,
		},
		{
			dir:            "anp_test_6",
			sourceNs:       "network-policy-conformance-slytherin",
			sourceWorkload: "draco-malfoy",
			destWorkload:   "cedric-diggory",
			destNs:         "network-policy-conformance-hufflepuff",
			protocol:       "udp",
			port:           "5353",
			evalResult:     false,
		},
		{
			dir:            "anp_test_multiple_anps",
			sourceNs:       "network-policy-conformance-ravenclaw",
			sourceWorkload: "luna-lovegood",
			destWorkload:   "draco-malfoy",
			destNs:         "network-policy-conformance-slytherin",
			protocol:       "sctp",
			port:           "9003",
			evalResult:     false,
		},
		{
			dir:            "anp_with_np_and_banp_pass_test",
			sourceNs:       "ns2",
			sourceWorkload: "pod1",
			destWorkload:   "pod1",
			destNs:         "ns1",
			port:           "80",
			evalResult:     true,
		},
		{
			dir:            "anp_with_np_pass_test",
			sourceNs:       "ns2",
			sourceWorkload: "pod1",
			destWorkload:   "pod1",
			destNs:         "ns1",
			port:           "8080",
			evalResult:     false,
		},
		{
			dir:            "anp_banp_core_test",
			sourceNs:       "network-policy-conformance-gryffindor",
			sourceWorkload: "harry-potter",
			destWorkload:   "cedric-diggory",
			destNs:         "network-policy-conformance-hufflepuff",
			port:           "8080",
			evalResult:     true,
		},
	}
	for _, tt := range cases {
		testName := "eval_" + tt.dir + "_from_" + tt.sourceWorkload + "_to_" + tt.destWorkload
		t.Run(testName, func(t *testing.T) {
			t.Parallel()
			if tt.protocol == "" {
				tt.protocol = strings.ToLower(string(v1.ProtocolTCP))
			}
			path := testutils.GetTestDirPath(tt.dir)
			rList, errs := fsscanner.GetResourceInfosFromDirPath([]string{path}, true, false)
			require.Empty(t, errs, "test: %q", testName)
			objectsList, processingErrs := parser.ResourceInfoListToK8sObjectsList(rList, logger.NewDefaultLogger(), false)
			require.Empty(t, processingErrs, "test: %q", testName)
			pe, err := NewPolicyEngineWithOptionsList(WithObjectsList(objectsList))
			require.Nil(t, err, "test: %q", testName)
			var src, dst string
			for podStr, podObj := range pe.podsMap {
				if podObj.Owner.Name == tt.sourceWorkload && podObj.Namespace == tt.sourceNs {
					src = podStr
				}
				if podObj.Owner.Name == tt.destWorkload && podObj.Namespace == tt.destNs {
					dst = podStr
				}
			}
			require.NotEmpty(t, src, "test %q, could not find pod for %s", testName, tt.sourceWorkload)
			require.NotEmpty(t, dst, "test %q, could not find pod for %s", testName, tt.destWorkload)
			res, err := pe.CheckIfAllowed(src, dst, tt.protocol, tt.port)
			require.Nil(t, err, "test: %q", testName)
			require.Equal(t, tt.evalResult, res, "unexpected result for test %q, should be %v", testName, tt.evalResult)
		})
	}
}
