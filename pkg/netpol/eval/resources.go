package eval

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval/internal/k8s"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/scan"
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

func NewPolicyEngineWithObjects(objects []scan.K8sObject) (*PolicyEngine, error) {
	pe := NewPolicyEngine()
	var err error
	for _, obj := range objects {
		switch obj.Kind {
		case scan.Namespace:
			err = pe.UpsertObject(obj.Namespace)
		case scan.Networkpolicy:
			err = pe.UpsertObject(obj.Networkpolicy)
		case scan.Pod:
			err = pe.UpsertObject(obj.Pod)
		case scan.ReplicaSet:
			err = pe.UpsertObject(obj.Replicaset)
		case scan.Deployment:
			err = pe.UpsertObject(obj.Deployment)
		case scan.Daemonset:
			err = pe.UpsertObject(obj.Daemonset)
		case scan.Statefulset:
			err = pe.UpsertObject(obj.Statefulset)
		case scan.ReplicationController:
			err = pe.UpsertObject(obj.ReplicationController)
		case scan.Job:
			err = pe.UpsertObject(obj.Job)
		case scan.CronJob:
			err = pe.UpsertObject(obj.CronJob)
		default:
			err = fmt.Errorf("unsupported kind: %s", obj.Kind)
		}
		if err != nil {
			return nil, err
		}
	}
	return pe, nil
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
	// namespace object
	case *corev1.Namespace:
		return pe.upsertNamespace(obj)
	// pod object
	case *corev1.Pod:
		return pe.upsertPod(obj)
	// netpol object
	case *netv1.NetworkPolicy:
		return pe.upsertNetworkPolicy(obj)
	// workload object
	case *appsv1.ReplicaSet:
		return pe.upsertWorkload(obj, scan.ReplicaSet)
	case *appsv1.Deployment:
		return pe.upsertWorkload(obj, scan.Deployment)
	case *appsv1.StatefulSet:
		return pe.upsertWorkload(obj, scan.Statefulset)
	case *appsv1.DaemonSet:
		return pe.upsertWorkload(obj, scan.Daemonset)
	case *corev1.ReplicationController:
		return pe.upsertWorkload(obj, scan.ReplicationController)
	case *batchv1.CronJob:
		return pe.upsertWorkload(obj, scan.CronJob)
	case *batchv1.Job:
		return pe.upsertWorkload(obj, scan.Job)
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

func (pe *PolicyEngine) upsertWorkload(rs interface{}, kind string) error {
	pods, err := k8s.PodsFromWorkloadObject(rs, kind)
	if err != nil {
		return err
	}
	for _, podObj := range pods {
		podStr := types.NamespacedName{Namespace: podObj.Namespace, Name: podObj.Name}
		pe.podsMap[podStr.String()] = podObj
		// update cache with new pod associated to to its owner
		pe.cache.addPod(podObj, podStr.String())
	}
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
// get peers in level of workloads (pod owners) of type WorkloadPeer, and ip-blocks
func (pe *PolicyEngine) GetPeersList() ([]Peer, error) {
	// create map from workload str to workload peer object
	podOwnersMap := make(map[string]Peer, 0)
	for _, pod := range pe.podsMap {
		workload := &k8s.WorkloadPeer{Pod: pod}
		podOwnersMap[workload.String()] = workload
	}

	ipBlocks := pe.GetDisjointIPBlocks()

	// add ip-blocks to peers list
	res := make([]Peer, len(ipBlocks)+len(podOwnersMap))
	for i := range ipBlocks {
		res[i] = &k8s.IPBlockPeer{IPBlock: ipBlocks[i]}
	}
	index := len(ipBlocks)
	// add workload peer objects to peers list
	for _, workloadPeer := range podOwnersMap {
		res[index] = workloadPeer
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
