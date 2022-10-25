package eval

import (
	appsv1 "k8s.io/api/apps/v1"
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

		// workloadsMap is for workload resources, directly from pod-creating resources (e.g. replicaset/deployment) as input resources
		workloadsMap map[string]*k8s.Workload // map from workload name to workload object

		// podOwnersMap is for pod owners resources, directly from pods resources as input resources
		podOwnersMap          map[string]*k8s.Workload // map from "owner-ns/owner-name/variant" to workload object
		podToWorkloadOwnerKey map[string]string        // map from pod name to its workload owner key in the podOwnersMap

		// cacheByWorkloads: for connectivity computation result
		cacheByWorkloads map[string]bool // map keys: "src/dst/protocol/port" as workloads (including variant per workload)
		cacheHitsCount   int             // for testing
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

// Resources is the set of all relevant k8s cluster resources
type Resources struct {
	npList         []*netv1.NetworkPolicy
	podList        []*corev1.Pod
	nsList         []*corev1.Namespace
	replicaSetList []*appsv1.ReplicaSet
	// TODO: add other resource types
	/*deploymentList            []*appsv1.Deployment
	daemonsetList             []*appsv1.DaemonSet
	statefulsetList           []*appsv1.StatefulSet
	jobList                   []*batchv1.Job
	cronJobList               []*batchv1.CronJob
	replicationControllerList []*corev1.ReplicationController*/
}

// NewPolicyEngine returns a new PolicyEngine with an empty initial state
func NewPolicyEngine() *PolicyEngine {
	return &PolicyEngine{
		namspacesMap:          make(map[string]*k8s.Namespace),
		podsMap:               make(map[string]*k8s.Pod),
		netpolsMap:            make(map[string]map[string]*k8s.NetworkPolicy),
		workloadsMap:          make(map[string]*k8s.Workload),
		podOwnersMap:          make(map[string]*k8s.Workload),
		podToWorkloadOwnerKey: make(map[string]string),
		cacheByWorkloads:      make(map[string]bool),
	}
}

// SetResources: updates the set of all relevant k8s resources
// This function *may* be used as convenience to set the initial policy engine state from a
// set of resources (e.g., retrieved via List from a cluster).
//
// Deprecated: this function simply calls UpsertObject on the PolicyEngine.
// Calling the UpsertObject should be preferred in new code.
func (pe *PolicyEngine) SetResources(resources *Resources) error {
	for i := range resources.nsList {
		if err := pe.upsertNamespace(resources.nsList[i]); err != nil {
			return err
		}
	}
	for i := range resources.npList {
		if err := pe.upsertNetworkPolicy(resources.npList[i]); err != nil {
			return err
		}
	}
	for i := range resources.podList {
		if err := pe.upsertPod(resources.podList[i]); err != nil {
			return err
		}
	}
	for i := range resources.replicaSetList {
		if err := pe.upsertReplicaSet(resources.replicaSetList[i]); err != nil {
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
	case *appsv1.ReplicaSet:
		return pe.upsertReplicaSet(obj)
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
	case *appsv1.ReplicaSet:
		return pe.deleteReplicaset(obj)
	}
	return nil
}

// ClearResources: deletes all current k8s resources
func (pe *PolicyEngine) ClearResources() {
	pe.namspacesMap = map[string]*k8s.Namespace{}
	pe.podsMap = map[string]*k8s.Pod{}
	pe.netpolsMap = map[string]map[string]*k8s.NetworkPolicy{}
	pe.workloadsMap = map[string]*k8s.Workload{}
	pe.podOwnersMap = map[string]*k8s.Workload{}
	pe.podToWorkloadOwnerKey = map[string]string{}
	pe.cacheByWorkloads = map[string]bool{}
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

	// check if pod has an owner workload or not
	// if not - create a workload owner for this pod
	hasOwner, podOwnerKey := pe.podHasWorkloadOwner(pod)
	if podOwnerKey == "" {
		// pod has no owner
		return nil
	}
	if !hasOwner {
		// create a workload owner for this pod
		podOwnerWorkload, err := k8s.WorkloadFromPodObject(pod)
		if err == nil && podOwnerWorkload != nil { // pod has owner
			pe.podOwnersMap[podOwnerKey] = podOwnerWorkload
		}
	} else { // increase counter of owned pods for existing workload object
		pe.podOwnersMap[podOwnerKey].CountOwnedPods += 1
	}
	// associate pod with existing/new workload owner object
	pe.podToWorkloadOwnerKey[podStr.String()] = podOwnerKey
	return nil
}

func (pe *PolicyEngine) podHasWorkloadOwner(pod *corev1.Pod) (bool, string) {
	podOwnerKey := k8s.GetPodOwnerKey(pod)
	if _, ok := pe.podOwnersMap[podOwnerKey]; !ok {
		return false, podOwnerKey
	}
	return true, podOwnerKey
}

func (pe *PolicyEngine) upsertReplicaSet(replicaset *appsv1.ReplicaSet) error {
	coreObj := &k8s.WorkloadK8sObject{Kind: "ReplicaSet", ReplicaSet: replicaset}
	workloadObj, err := k8s.WorkloadFromCoreObject(coreObj)
	if err != nil {
		return err
	}
	workloadStr := types.NamespacedName{Namespace: workloadObj.Namespace, Name: workloadObj.Name}
	pe.workloadsMap[workloadStr.String()] = workloadObj
	return nil
}

func (pe *PolicyEngine) upsertNetworkPolicy(np *netv1.NetworkPolicy) error {
	netpolNamespace := np.ObjectMeta.Namespace
	if netpolNamespace == "" {
		netpolNamespace = metav1.NamespaceDefault
		np.ObjectMeta.Namespace = netpolNamespace
	}
	if _, ok := pe.netpolsMap[netpolNamespace]; !ok {
		pe.netpolsMap[netpolNamespace] = map[string]*k8s.NetworkPolicy{np.Name: (*k8s.NetworkPolicy)(np)}
	} else {
		pe.netpolsMap[netpolNamespace][np.Name] = (*k8s.NetworkPolicy)(np)
	}
	return nil
}

func (pe *PolicyEngine) deleteNamespace(ns *corev1.Namespace) error {
	delete(pe.namspacesMap, ns.Name)
	return nil
}

func (pe *PolicyEngine) deletePod(p *corev1.Pod) error {
	podNameKey := types.NamespacedName{Namespace: p.Namespace, Name: p.Name}.String()
	delete(pe.podsMap, podNameKey)
	podOwnerKey := pe.podToWorkloadOwnerKey[podNameKey]
	pe.podOwnersMap[podOwnerKey].CountOwnedPods -= 1
	// check if should delete the workload owner associated with this pod
	if pe.podOwnersMap[podOwnerKey].CountOwnedPods == 0 {
		delete(pe.podOwnersMap, podOwnerKey)
	}
	delete(pe.podToWorkloadOwnerKey, podNameKey)

	return nil
}

func (pe *PolicyEngine) deleteReplicaset(rs *appsv1.ReplicaSet) error {
	delete(pe.workloadsMap, types.NamespacedName{Namespace: rs.Namespace, Name: rs.Name}.String())
	return nil
}

func (pe *PolicyEngine) deleteNetworkPolicy(np *netv1.NetworkPolicy) error {
	if policiesMap, ok := pe.netpolsMap[np.Namespace]; ok {
		delete(policiesMap, np.Name)
		if len(policiesMap) == 0 {
			delete(pe.netpolsMap, np.Namespace)
		}
	}
	return nil
}

// get from a peer which is of pod type, a peer of workload type (owner of the pod)
func (pe *PolicyEngine) peerConvertPodToOwnerWorkload(peer *k8s.Peer) (*k8s.Peer, bool) {
	if peer.PeerType != k8s.PodType {
		return peer, false
	}
	newPeer := &k8s.Peer{}
	// look for the pod owner
	podFullName := types.NamespacedName{Namespace: peer.Pod.Namespace, Name: peer.Pod.Name}.String()
	if podOwnerKey, ok := pe.podToWorkloadOwnerKey[podFullName]; ok {
		if workloadOwner, ok := pe.podOwnersMap[podOwnerKey]; ok {
			newPeer.Workload = workloadOwner
			newPeer.PeerType = k8s.WorkloadType
			newPeer.Namespace = peer.Namespace
			return newPeer, true
		}
	}
	return peer, false
}
