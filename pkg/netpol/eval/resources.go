/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package eval

import (
	"errors"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"github.com/np-guard/models/pkg/ipblock"

	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/parser"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval/internal/k8s"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

type (
	// PolicyEngine encapsulates the current "world view" (e.g., workloads, policies)
	// and allows querying it for allowed or denied connections.
	PolicyEngine struct {
		namspacesMap                    map[string]*k8s.Namespace                // map from ns name to ns object
		podsMap                         map[string]*k8s.Pod                      // map from pod name to pod object
		netpolsMap                      map[string]map[string]*k8s.NetworkPolicy // map from namespace to map from netpol name to its object
		podOwnersToRepresentativePodMap map[string]map[string]*k8s.Pod           // map from namespace to map from pods' ownerReference name
		// to its representative pod object
		cache                  *evalCache
		exposureAnalysisFlag   bool
		representativePeersMap map[string]*k8s.RepresentativePeer // map from unique labels string to representative peer object,
		// used only with exposure analysis
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
		namspacesMap:                    make(map[string]*k8s.Namespace),
		podsMap:                         make(map[string]*k8s.Pod),
		netpolsMap:                      make(map[string]map[string]*k8s.NetworkPolicy),
		podOwnersToRepresentativePodMap: make(map[string]map[string]*k8s.Pod),
		cache:                           newEvalCache(),
		exposureAnalysisFlag:            false,
	}
}

func NewPolicyEngineWithObjects(objects []parser.K8sObject) (*PolicyEngine, error) {
	pe := NewPolicyEngine()
	err := pe.addObjectsByKind(objects)
	return pe, err
}

// NewPolicyEngineWithOptions returns a new policy engine with an empty state but updating the exposure analysis flag
// TBD: currently exposure-analysis is the only option supported by policy-engine, so no need for options list param
func NewPolicyEngineWithOptions(exposureFlag bool) *PolicyEngine {
	pe := NewPolicyEngine()
	pe.exposureAnalysisFlag = exposureFlag
	if exposureFlag {
		pe.representativePeersMap = make(map[string]*k8s.RepresentativePeer)
	}
	return pe
}

// AddObjects adds k8s objects to the policy engine: first adds network-policies and namespaces and then other objects
// called only for exposure analysis; otherwise does nothing
// for exposure analysis we need to upsert first policies and namespaces so:
// 1. policies: so representative peer for each policy rule is added
// 2. namespaces: so when upserting workloads, we'll be able to refine correctly representativePeers with
// namespace name/ labels similar to those belonging the workloads' namespace
func (pe *PolicyEngine) AddObjects(objects []parser.K8sObject) error {
	if !pe.exposureAnalysisFlag { // should not be true ever
		return nil
	}
	policiesAndNamespaces, otherObjects := splitPoliciesAndNamespacesAndOtherObjects(objects)
	err := pe.addObjectsByKind(policiesAndNamespaces)
	if err != nil {
		return err
	}
	err = pe.addObjectsByKind(otherObjects)
	return err
}

func splitPoliciesAndNamespacesAndOtherObjects(objects []parser.K8sObject) (policiesAndNs, others []parser.K8sObject) {
	for _, obj := range objects {
		switch obj.Kind {
		case parser.Networkpolicy:
			policiesAndNs = append(policiesAndNs, obj)
		case parser.Namespace:
			policiesAndNs = append(policiesAndNs, obj)
		default:
			others = append(others, obj)
		}
	}
	return policiesAndNs, others
}

// addObjectsByKind adds different k8s objects from parsed resources to the policy engine
func (pe *PolicyEngine) addObjectsByKind(objects []parser.K8sObject) error {
	var err error
	for _, obj := range objects {
		switch obj.Kind {
		case parser.Namespace:
			err = pe.UpsertObject(obj.Namespace)
		case parser.Networkpolicy:
			err = pe.UpsertObject(obj.Networkpolicy)
		case parser.Pod:
			err = pe.UpsertObject(obj.Pod)
		case parser.ReplicaSet:
			err = pe.UpsertObject(obj.Replicaset)
		case parser.Deployment:
			err = pe.UpsertObject(obj.Deployment)
		case parser.Daemonset:
			err = pe.UpsertObject(obj.Daemonset)
		case parser.Statefulset:
			err = pe.UpsertObject(obj.Statefulset)
		case parser.ReplicationController:
			err = pe.UpsertObject(obj.ReplicationController)
		case parser.Job:
			err = pe.UpsertObject(obj.Job)
		case parser.CronJob:
			err = pe.UpsertObject(obj.CronJob)
		case parser.Service, parser.Route, parser.Ingress:
			continue
		default:
			fmt.Printf("ignoring resource kind %s", obj.Kind)
		}
		if err != nil {
			return err
		}
	}
	if !pe.exposureAnalysisFlag { // for exposure analysis; this already done
		return pe.resolveMissingNamespaces()
	}
	return nil
}

func (pe *PolicyEngine) resolveMissingNamespaces() error {
	for _, pod := range pe.podsMap {
		ns := pod.Namespace
		if _, ok := pe.namspacesMap[ns]; !ok {
			if err := pe.resolveSingleMissingNamespace(ns); err != nil {
				return err
			}
		}
	}
	return nil
}

// resolveSingleMissingNamespace create a ns object and upsert to PolicyEngine
func (pe *PolicyEngine) resolveSingleMissingNamespace(ns string) error {
	nsObj := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: ns,
			Labels: map[string]string{
				common.K8sNsNameLabelKey: ns,
			},
		},
	}
	if err := pe.upsertNamespace(nsObj); err != nil {
		return err
	}
	return nil
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
		return pe.upsertWorkload(obj, parser.ReplicaSet)
	case *appsv1.Deployment:
		return pe.upsertWorkload(obj, parser.Deployment)
	case *appsv1.StatefulSet:
		return pe.upsertWorkload(obj, parser.Statefulset)
	case *appsv1.DaemonSet:
		return pe.upsertWorkload(obj, parser.Daemonset)
	case *corev1.ReplicationController:
		return pe.upsertWorkload(obj, parser.ReplicationController)
	case *batchv1.CronJob:
		return pe.upsertWorkload(obj, parser.CronJob)
	case *batchv1.Job:
		return pe.upsertWorkload(obj, parser.Job)
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
	pe.podOwnersToRepresentativePodMap = make(map[string]map[string]*k8s.Pod)
	if pe.exposureAnalysisFlag {
		pe.representativePeersMap = make(map[string]*k8s.RepresentativePeer)
	}
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

// checkConsistentLabelsForPodsOfSameOwner returns error if there are pod resources with same ownerReferences name but different labels
func (pe *PolicyEngine) checkConsistentLabelsForPodsOfSameOwner(newPod *k8s.Pod) error {
	if newPod.Owner.Name == "" { // the new pod does not have owner references
		return nil
	}
	if _, ok := pe.podOwnersToRepresentativePodMap[newPod.Namespace]; !ok { // add the new namespace to the map
		pe.podOwnersToRepresentativePodMap[newPod.Namespace] = make(map[string]*k8s.Pod)
	}
	firstPod, ok := pe.podOwnersToRepresentativePodMap[newPod.Namespace][newPod.Owner.Name]
	if !ok { // add the new ownerReference with this new pod
		pe.podOwnersToRepresentativePodMap[newPod.Namespace][newPod.Owner.Name] = newPod
		return nil
	}
	// compare the owner first pod's labels with new pod's Labels
	if key, firstVal, newVal := diffBetweenPodsLabels(firstPod, newPod); key != "" {
		return generateLabelsDiffError(firstPod, newPod, key, firstVal, newVal) // err
	}
	return nil
}

// helper: generateLabelsDiffError generates the error message of the gap between two pods' labels
func generateLabelsDiffError(firstPod, newPod *k8s.Pod, key, firstVal, newVal string) error {
	// helping vars declarations to avoid duplicates
	ownerName := types.NamespacedName{Namespace: firstPod.Namespace, Name: firstPod.Owner.Name}.String()
	newPodStr := types.NamespacedName{Namespace: newPod.Namespace, Name: newPod.Name}.String()
	firstPodStr := types.NamespacedName{Namespace: firstPod.Namespace, Name: firstPod.Name}.String()
	errMsgPart1 := netpolerrors.NotSupportedPodResourcesErrorStr(ownerName)
	errMsgPart2 := ""
	keyMissingErr := " Pod %s has label %s=%s, and Pod %s does not have label %s."
	differentValuesErr := " Pod %s has label %s=%s, and Pod %s has label %s=%s."
	switch {
	case firstVal == "":
		errMsgPart2 = fmt.Sprintf(keyMissingErr, newPodStr, key, newVal, firstPodStr, key)
	case newVal == "":
		errMsgPart2 = fmt.Sprintf(keyMissingErr, firstPodStr, key, firstVal, newPodStr, key)
	default: // both values are not empty
		errMsgPart2 = fmt.Sprintf(differentValuesErr, newPodStr, key, newVal, firstPodStr, key, firstVal)
	}
	return errors.New(errMsgPart1 + errMsgPart2)
}

// helper: given two pods of same owner, if there are diffs between the pods' labels maps returns first captured diff components,
// i.e. the different label's key and the different values / empty val if the key is missing in one pod's labels;
// if there is no diff, returns empty key (with empty values)
func diffBetweenPodsLabels(firstPod, newPod *k8s.Pod) (key, firstVal, newVal string) {
	// try to find diffs by looping new pod's labels first
	for key, value := range newPod.Labels {
		if _, ok := firstPod.Labels[key]; !ok {
			return key, "", value
		}
		if firstPod.Labels[key] != value {
			return key, firstPod.Labels[key], value
		}
	}
	// check if first pod's labels contains keys which are not in the new pod's labels
	for key, val := range firstPod.Labels {
		if _, ok := newPod.Labels[key]; !ok {
			return key, val, ""
		}
	}
	return "", "", ""
}

func (pe *PolicyEngine) upsertWorkload(rs interface{}, kind string) error {
	pods, err := k8s.PodsFromWorkloadObject(rs, kind)
	if err != nil {
		return err
	}
	var podObj *k8s.Pod
	for _, podObj = range pods {
		podStr := types.NamespacedName{Namespace: podObj.Namespace, Name: podObj.Name}
		pe.podsMap[podStr.String()] = podObj
		// update cache with new pod associated to to its owner
		pe.cache.addPod(podObj, podStr.String())
	}
	// running this on last podObj: as all pods from same workload object are in same namespace and having same pod labels
	if pe.exposureAnalysisFlag {
		err = pe.extractLabelsAndRefineRepresentativePeers(podObj)
	}
	return err
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
	if pe.exposureAnalysisFlag {
		err = pe.extractLabelsAndRefineRepresentativePeers(podObj)
	}
	return err
}

func initPolicyGeneralConns() k8s.PolicyGeneralRulesConns {
	return k8s.PolicyGeneralRulesConns{
		AllDestinationsConns: common.MakeConnectionSet(false),
		EntireClusterConns:   common.MakeConnectionSet(false),
	}
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

	newNetpol := &k8s.NetworkPolicy{
		NetworkPolicy:       np,
		IngressGeneralConns: initPolicyGeneralConns(),
		EgressGeneralConns:  initPolicyGeneralConns(),
	}
	pe.netpolsMap[netpolNamespace][np.Name] = newNetpol

	var err error
	// for exposure analysis only: scan policy ingress and egress rules:
	// 1. to store allowed connections to entire cluster and to all destinations (if such connections are allowed by the policy)
	// 2. to get selectors and generate representativePeers
	if pe.exposureAnalysisFlag {
		rulesSelectors, scanErr := newNetpol.ScanPolicyRulesForGeneralConnsAndRepresentativePeers()
		if scanErr != nil {
			return scanErr
		}
		err = pe.generateRepresentativePeers(rulesSelectors, np.Namespace)
	}
	// clear the cache on netpols changes
	pe.cache.clear()
	return err
}

func (pe *PolicyEngine) deleteNamespace(ns *corev1.Namespace) error {
	delete(pe.namspacesMap, ns.Name)
	return nil
}

func (pe *PolicyEngine) deletePod(p *corev1.Pod) error {
	podName := types.NamespacedName{Namespace: p.Namespace, Name: p.Name}.String()
	var podToDelete *k8s.Pod
	if podObj, ok := pe.podsMap[podName]; ok {
		// delete relevant workload entries from cache if all pods per owner are deleted
		pe.cache.deletePod(podObj, podName)
		podToDelete = podObj
	}

	delete(pe.podsMap, podName)
	pe.updatePodOwnersToRepresentativePodMapIfRequired(podToDelete)
	return nil
}

// updates podOwnersToRepresentativePodMap as required, if the deleted pod was a representative of the ownerRef.
// then it will be replace if another pod of same owner exists, otherwise the owner ref. entry will be deleted from the map
// the deletedPod already deleted from pe.podsMap
func (pe *PolicyEngine) updatePodOwnersToRepresentativePodMapIfRequired(deletedPod *k8s.Pod) {
	// all existing pods' owners are in the map already
	representativePod := pe.podOwnersToRepresentativePodMap[deletedPod.Namespace][deletedPod.Owner.Name]
	if deletedPod != representativePod { // this was not the representative pod, no need to update
		return
	}
	// deletedPod was the representative pods:
	// check in pe.podsMap if there are other pods belonging to same owner
	for _, pod := range pe.podsMap {
		if pod.Namespace == deletedPod.Namespace && pod.Owner.Name == deletedPod.Owner.Name {
			// replace the representative pod with current pod
			pe.podOwnersToRepresentativePodMap[deletedPod.Namespace][deletedPod.Owner.Name] = pod
			return
		}
	}
	// if we get here no remaining pods with same owner, delete the owner entry
	delete(pe.podOwnersToRepresentativePodMap[deletedPod.Namespace], deletedPod.Owner.Name)
	// if it was the only owner under ns delete the ns entry
	if len(pe.podOwnersToRepresentativePodMap[deletedPod.Namespace]) == 0 {
		delete(pe.podOwnersToRepresentativePodMap, deletedPod.Namespace)
	}
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

// HasPodPeers returns if there are pods from parsed pod objects in the policy-engine
func (pe *PolicyEngine) HasPodPeers() bool {
	return len(pe.podsMap) > 0
}

// createPodOwnersMap creates map from workload str to workload peer object
// returns error if there are two pods of same owner but different set of labels, since cannot map inconsistent pods to a workload
func (pe *PolicyEngine) createPodOwnersMap() (map[string]Peer, error) {
	res := make(map[string]Peer, 0)
	for _, pod := range pe.podsMap {
		if err := pe.checkConsistentLabelsForPodsOfSameOwner(pod); err != nil {
			return nil, err
		}
		workload := &k8s.WorkloadPeer{Pod: pod}
		res[workload.String()] = workload
	}
	return res, nil
}

// GetPeersList returns a slice of peers from all PolicyEngine resources
// get peers in level of workloads (pod owners) of type WorkloadPeer, and ip-blocks
func (pe *PolicyEngine) GetPeersList() ([]Peer, error) {
	podOwnersMap, err := pe.createPodOwnersMap()
	if err != nil {
		return nil, err
	}
	ipBlocks, err := pe.getDisjointIPBlocks()
	if err != nil {
		return nil, err
	}

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

// GetRepresentativePeersList returns a slice of representative peers
func (pe *PolicyEngine) GetRepresentativePeersList() []Peer {
	res := make([]Peer, len(pe.representativePeersMap))
	index := 0
	for _, p := range pe.representativePeersMap {
		res[index] = p
		index++
	}
	return res
}

// getDisjointIPBlocks returns a slice of disjoint ip-blocks from all netpols resources
func (pe *PolicyEngine) getDisjointIPBlocks() ([]*ipblock.IPBlock, error) {
	var ipbList []*ipblock.IPBlock
	for _, nsMap := range pe.netpolsMap {
		for _, policy := range nsMap {
			policyIPBlocksList, err := policy.GetReferencedIPBlocks()
			if err != nil {
				return nil, err
			}
			ipbList = append(ipbList, policyIPBlocksList...)
		}
	}
	newAll := ipblock.GetCidrAll()
	disjointRes := ipblock.DisjointIPBlocks(ipbList, []*ipblock.IPBlock{newAll})
	return disjointRes, nil
}

// GetSelectedPeers returns list of workload peers in the given namespace which match the given labels selector
// used only for ingress-analyzer : currently not supported with exposure-analysis
func (pe *PolicyEngine) GetSelectedPeers(selectors labels.Selector, namespace string) ([]Peer, error) {
	res := make([]Peer, 0)
	peers, err := pe.createPodOwnersMap()
	if err != nil {
		return nil, err
	}
	for _, peer := range peers {
		if peer.Namespace() != namespace {
			continue
		}
		if selectors.Matches(labels.Set(peer.(*k8s.WorkloadPeer).Pod.Labels)) {
			res = append(res, peer)
		}
	}
	return res, nil
}

// ConvertPeerNamedPort returns the peer.pod.containerPort matching the named port of the peer
// if there is no match for the input named port, return -1
func (pe *PolicyEngine) ConvertPeerNamedPort(namedPort string, peer Peer) (int32, error) {
	switch currPeer := peer.(type) {
	case *k8s.WorkloadPeer:
		return currPeer.Pod.ConvertPodNamedPort(namedPort), nil
	case *k8s.PodPeer:
		return currPeer.Pod.ConvertPodNamedPort(namedPort), nil
	default:
		return 0, errors.New("peer type does not have ports") // should not get here
	}
}

// AddPodByNameAndNamespace adds a new fake pod to the pe.podsMap, used for adding ingress-controller pod
func (pe *PolicyEngine) AddPodByNameAndNamespace(name, ns string) (Peer, error) {
	podStr := types.NamespacedName{Namespace: ns, Name: name}.String()
	newPod := &k8s.Pod{
		Name:      name,
		Namespace: ns,
		FakePod:   true,
	}
	if err := pe.resolveSingleMissingNamespace(ns); err != nil {
		return nil, err
	}
	pe.podsMap[podStr] = newPod
	return &k8s.WorkloadPeer{Pod: newPod}, nil
}

// addRepresentativePod adds a new representative pod to the policy-engine (to pe.representativePeersMap)
// if the given namespace string (ns) is not empty (i.e. a real namespace name), the representative pod is created in that namespace
// else, the representative pod will have no namespace (will not add a representative namespace to the policy-engine)
// and its "namespace" requirements will be stored in its RepresentativeNsLabelSelector field to be used when needed
// used only in exposure-analysis
func (pe *PolicyEngine) addRepresentativePod(name, ns string, objSelectors *k8s.SingleRuleSelectors) error {
	var nsSelector, podSelector *metav1.LabelSelector
	if objSelectors != nil {
		nsSelector = objSelectors.NsSelector
		podSelector = objSelectors.PodSelector
	}
	newPod := &k8s.Pod{
		Name:                           name,
		Namespace:                      ns,
		FakePod:                        true,
		RepresentativePodLabelSelector: podSelector,
		RepresentativeNsLabelSelector:  nsSelector,
	}
	if ns != "" { // if the policy namespace is not in the policy-engine yet, add it (as it is a real namespace)
		if err := pe.resolveSingleMissingNamespace(ns); err != nil {
			return err
		}
	}

	//  compute a unique string from the label selectors to be used as the map key
	nsKey, err := k8s.VariantFromLabelsSelector(nsSelector)
	if err != nil {
		return err
	}
	podKey, err := k8s.VariantFromLabelsSelector(podSelector)
	if err != nil {
		return err
	}
	keyStrFromLabels := nsKey + "/" + podKey
	if _, ok := pe.representativePeersMap[keyStrFromLabels]; ok { // we already have a representative peer with same labels
		return nil
	}
	// create a new representative peer
	newRepresentativePeer := &k8s.RepresentativePeer{Pod: newPod,
		PotentialNamespaceLabelSelector: nsSelector}
	// add the new representative peer to the policy-engine
	pe.representativePeersMap[keyStrFromLabels] = newRepresentativePeer
	return nil
}
