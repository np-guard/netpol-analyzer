package eval

import (
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval/internal/k8s"
)

type (
	// PolicyEngine encapsulates the current "world view" (e.g., workloads, policies)
	// and allows querying it for allowed or denied connections.
	PolicyEngine struct {
		namspacesMap map[string]*k8s.Namespace       // map from ns name to ns object
		podsMap      map[string]*k8s.Pod             // map from pod name to pod object
		netpolsMap   map[string][]*k8s.NetworkPolicy // map from netpol's namespace to netpol object
	}
)

// NewPolicyEngine returns a new PolicyEngine with an empty initial state
func NewPolicyEngine() *PolicyEngine {
	return &PolicyEngine{
		namspacesMap: make(map[string]*k8s.Namespace),
		podsMap:      make(map[string]*k8s.Pod),
		netpolsMap:   make(map[string][]*k8s.NetworkPolicy),
	}
}

// SetResources: updates the set of all relevant k8s resources
func (pe *PolicyEngine) SetResources(policies []*netv1.NetworkPolicy, pods []*corev1.Pod,
	namespaces []*corev1.Namespace) error {
	for i := range namespaces {
		if err := pe.upsertNamespace(namespaces[i]); err != nil {
			return err
		}
	}
	for i := range policies {
		if err := pe.upsertNetworkPolicy(policies[i]); err != nil {
			return err
		}
	}
	for i := range pods {
		if err := pe.upsertPod(pods[i]); err != nil {
			return err
		}
	}

	return nil
}

// ClearResources: deletes all current k8s resources
func (pe *PolicyEngine) ClearResources() {
	pe.namspacesMap = map[string]*k8s.Namespace{}
	pe.podsMap = map[string]*k8s.Pod{}
	pe.netpolsMap = map[string][]*k8s.NetworkPolicy{}
}

func (pe *PolicyEngine) upsertNamespace(ns *corev1.Namespace) error {
	nsObj, err := k8s.NamespaceFromCoreObject(ns)
	if err != nil {
		return err
	}
	pe.namspacesMap[nsObj.Name] = nsObj
	return nil
}

func (pe *PolicyEngine) upsertPod(pod *corev1.Pod) error {
	podObj, err := k8s.PodFromCoreObject(pod)
	if err != nil {
		return err
	}
	podStr := types.NamespacedName{Namespace: podObj.Namespace, Name: podObj.Name}
	pe.podsMap[podStr.String()] = podObj
	return nil
}

func (pe *PolicyEngine) upsertNetworkPolicy(np *netv1.NetworkPolicy) error {
	netpolNamespace := np.ObjectMeta.Namespace
	if netpolNamespace == "" {
		netpolNamespace = defaultNamespace
		np.ObjectMeta.Namespace = defaultNamespace
	}
	if _, ok := pe.netpolsMap[netpolNamespace]; !ok {
		pe.netpolsMap[netpolNamespace] = []*k8s.NetworkPolicy{(*k8s.NetworkPolicy)(np)}
	} else {
		pe.netpolsMap[netpolNamespace] = append(pe.netpolsMap[netpolNamespace], (*k8s.NetworkPolicy)(np))
	}
	return nil
}
