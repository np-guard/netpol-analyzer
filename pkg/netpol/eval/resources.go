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
		pods         []*k8s.Pod
		namespaces   []*k8s.Namespace
		namspacesMap map[string]*k8s.Namespace       // map from ns name to ns object
		podsMap      map[string]*k8s.Pod             // map from pod name to pod object
		netpolsMap   map[string][]*k8s.NetworkPolicy // map from netpol's namespace to netpol object
	}
)

// NewPolicyEngine returns a new PolicyEngine with an empty initial state
func NewPolicyEngine() *PolicyEngine {
	return &PolicyEngine{
		pods:         []*k8s.Pod{},
		namespaces:   []*k8s.Namespace{},
		namspacesMap: make(map[string]*k8s.Namespace),
		podsMap:      make(map[string]*k8s.Pod),
		netpolsMap:   make(map[string][]*k8s.NetworkPolicy),
	}
}

// SetResources: updates the set of all relevant k8s resources
func (pe *PolicyEngine) SetResources(npList []*netv1.NetworkPolicy, podList []*corev1.Pod, nsList []*corev1.Namespace) error {
	for i := range npList {
		netpolNamespace := npList[i].ObjectMeta.Namespace
		if netpolNamespace == "" {
			netpolNamespace = defaultNamespace
			npList[i].ObjectMeta.Namespace = defaultNamespace
		}
		if _, ok := pe.netpolsMap[netpolNamespace]; !ok {
			pe.netpolsMap[netpolNamespace] = []*k8s.NetworkPolicy{(*k8s.NetworkPolicy)(npList[i])}
		} else {
			pe.netpolsMap[netpolNamespace] = append(pe.netpolsMap[netpolNamespace], (*k8s.NetworkPolicy)(npList[i]))
		}
	}
	for i := range podList {
		podObj, err := k8s.PodFromCoreObject(podList[i])
		if err != nil {
			return err
		}
		pe.pods = append(pe.pods, podObj)
		podStr := types.NamespacedName{Namespace: podObj.Namespace, Name: podObj.Name}
		pe.podsMap[podStr.String()] = podObj
	}

	for i := range nsList {
		nsObj, err := k8s.NamespaceFromCoreObject(nsList[i])
		if err != nil {
			return err
		}
		pe.namespaces = append(pe.namespaces, nsObj)
		pe.namspacesMap[nsObj.Name] = nsObj
	}

	return nil
}

// ClearResources: deletes all current k8s resources
func (pe *PolicyEngine) ClearResources() {
	pe.pods = []*k8s.Pod{}
	pe.namespaces = []*k8s.Namespace{}
	pe.namspacesMap = map[string]*k8s.Namespace{}
	pe.podsMap = map[string]*k8s.Pod{}
	pe.netpolsMap = map[string][]*k8s.NetworkPolicy{}
}
