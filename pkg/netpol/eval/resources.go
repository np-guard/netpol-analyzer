package eval

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval/internal/k8s"
)

type (
	// PolicyEngine encapsulates the current "world view" (e.g., workloads, policies)
	// and allows querying it for allowed or denied connections.
	PolicyEngine struct {
		namspacesMap map[string]*k8s.Namespace                // map from ns name to ns object
		podsMap      map[string]*k8s.Pod                      // map from pod name to pod object
		netpolsMap   map[string]map[string]*k8s.NetworkPolicy // map from namespace to map from netpol name to its object

		cache *evalCache
	}

	// NotificationTarget defines an interface for updating the state needed for network policy
	// decisions
	NotificationTarget interface {
		// UpsertObject inserts (or updates) an object to the policy engine's view of the world
		UpsertObject(obj runtime.Object) error
		// DeleteObject removes an object from the policy engine's view of the world
		DeleteObject(obj runtime.Object) error
	}
)

// NewPolicyEngine returns a new PolicyEngine with an empty initial state
func NewPolicyEngine() *PolicyEngine {
	return &PolicyEngine{
		namspacesMap: make(map[string]*k8s.Namespace),
		podsMap:      make(map[string]*k8s.Pod),
		netpolsMap:   make(map[string]map[string]*k8s.NetworkPolicy),
		cache:        newEvalCache(),
	}
}

// SetResources: updates the set of all relevant k8s resources
// This function *may* be used as convenience to set the initial policy engine state from a
// set of resources (e.g., retrieved via List from a cluster).
//
// Deprecated: this function simply calls UpsertObject on the PolicyEngine.
// Calling the UpsertObject should be preferred in new code.
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

// UpsertObject updates (an existing) or inserts (a new) object in the PolicyEngine's
// view of the world
func (pe *PolicyEngine) UpsertObject(rtobj runtime.Object) error {
	switch obj := rtobj.(type) {
	case *corev1.Namespace:
		return pe.upsertNamespace(obj)
	case *corev1.Pod:
		return pe.upsertPod(obj)
	case *netv1.NetworkPolicy:
		return pe.upsertNetworkPolicy(obj)
	}
	return nil
}

// DeleteObject removes an object from the PolicyEngine's view of the world
func (pe *PolicyEngine) DeleteObject(rtobj runtime.Object) error {
	switch obj := rtobj.(type) {
	case *corev1.Namespace:
		return pe.deleteNamespace(obj)
	case *corev1.Pod:
		return pe.deletePod(obj)
	case *netv1.NetworkPolicy:
		return pe.deleteNetworkPolicy(obj)
	}
	return nil
}

// ClearResources: deletes all current k8s resources
func (pe *PolicyEngine) ClearResources() {
	pe.namspacesMap = make(map[string]*k8s.Namespace)
	pe.podsMap = make(map[string]*k8s.Pod)
	pe.netpolsMap = make(map[string]map[string]*k8s.NetworkPolicy)
	pe.cache = newEvalCache()
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
	// update cache with new pod associated to to its owner
	pe.cache.addPod(podObj, podStr.String())
	return nil
}

func (pe *PolicyEngine) upsertNetworkPolicy(np *netv1.NetworkPolicy) error {
	netpolNamespace := np.ObjectMeta.Namespace
	if netpolNamespace == "" {
		netpolNamespace = metav1.NamespaceDefault
		np.ObjectMeta.Namespace = netpolNamespace
	}
	if _, ok := pe.netpolsMap[netpolNamespace]; !ok {
		pe.netpolsMap[netpolNamespace] = make(map[string]*k8s.NetworkPolicy)
	}
	pe.netpolsMap[netpolNamespace][np.Name] = (*k8s.NetworkPolicy)(np)

	// clear the cache on netpols changes
	pe.cache.clear()
	return nil
}

func (pe *PolicyEngine) deleteNamespace(ns *corev1.Namespace) error {
	delete(pe.namspacesMap, ns.Name)
	return nil
}

func (pe *PolicyEngine) deletePod(p *corev1.Pod) error {
	podName := types.NamespacedName{Namespace: p.Namespace, Name: p.Name}.String()

	if podObj, ok := pe.podsMap[podName]; ok {
		// delete relevant workload entries from cache if all pods per owner are deleted
		pe.cache.deletePod(podObj, podName)
	}

	delete(pe.podsMap, podName)
	return nil
}

func (pe *PolicyEngine) deleteNetworkPolicy(np *netv1.NetworkPolicy) error {
	if policiesMap, ok := pe.netpolsMap[np.Namespace]; ok {
		delete(policiesMap, np.Name)
		if len(policiesMap) == 0 {
			delete(pe.netpolsMap, np.Namespace)
		}
	}

	// clear the cache on netpols changes
	pe.cache.clear()
	return nil
}

// GetPodsMap: return map of pods within PolicyEngine
func (pe *PolicyEngine) GetPodsMap() map[string]*k8s.Pod {
	return pe.podsMap
}

// GetPeersList returns a slice of peers from all PolicyEngine resources
func (pe *PolicyEngine) GetPeersList() ([]*k8s.Peer, error) {
	ipBlocks := pe.GetDisjointIPBlocks()
	res := make([]*k8s.Peer, len(ipBlocks)+len(pe.podsMap))
	for i := range ipBlocks {
		res[i] = &k8s.Peer{IPBlock: ipBlocks[i], PeerType: k8s.IPBlockType}
	}
	index := len(ipBlocks)
	for podName, pod := range pe.podsMap {
		podNamespace, ok := pe.namspacesMap[pod.Namespace]
		if !ok {
			return nil, fmt.Errorf("error: namespace of pod %v is missing", podName)
		}
		res[index] = &k8s.Peer{Pod: pod, Namespace: podNamespace, PeerType: k8s.PodType}
		index++
	}
	return res, nil
}

// GetDisjointIPBlocks returns a slice of disjoint ip-blocks from all netpols resources
func (pe *PolicyEngine) GetDisjointIPBlocks() []*k8s.IPBlock {
	var ipbList []*k8s.IPBlock
	for _, nsMap := range pe.netpolsMap {
		for _, policy := range nsMap {
			policyIPBlocksList := policy.GetReferencedIPBlocks()
			ipbList = append(ipbList, policyIPBlocksList...)
		}
	}
	newAll, _ := k8s.NewIPBlock("0.0.0.0/0", []string{})
	disjointRes := k8s.DisjointIPBlocks(ipbList, []*k8s.IPBlock{newAll})
	return disjointRes
}

// IsPeerIPType returns true for an input peer if it is an IP type
func IsPeerIPType(peer *k8s.Peer) bool {
	return peer.PeerType == k8s.IPBlockType
}
