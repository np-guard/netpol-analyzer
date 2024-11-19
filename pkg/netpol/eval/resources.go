/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package eval

import (
	"errors"
	"fmt"
	"sort"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	apisv1a "sigs.k8s.io/network-policy-api/apis/v1alpha1"

	"github.com/np-guard/models/pkg/netset"

	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
	"github.com/np-guard/netpol-analyzer/pkg/logger"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/parser"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval/internal/k8s"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

type (
	// PolicyEngine encapsulates the current "world view" (e.g., workloads, policies)
	// and allows querying it for allowed or denied connections.
	PolicyEngine struct {
		logger                          logger.Logger
		namespacesMap                   map[string]*k8s.Namespace                // map from ns name to ns object
		podsMap                         map[string]*k8s.Pod                      // map from pod name to pod object
		netpolsMap                      map[string]map[string]*k8s.NetworkPolicy // map from namespace to map from netpol name to its object
		podOwnersToRepresentativePodMap map[string]map[string]*k8s.Pod           // map from namespace to map from pods' ownerReference name
		// to its representative pod object
		adminNetpolsMap    map[string]bool           // set of input admin-network-policies names to ensure uniqueness by name
		sortedAdminNetpols []*k8s.AdminNetworkPolicy // sorted by priority list of admin-network-policies;
		// sorting ANPs occurs after all input k8s objects are inserted to the policy-engine
		baselineAdminNetpol    *k8s.BaselineAdminNetworkPolicy // pointer to BaselineAdminNetworkPolicy which is a cluster singleton object
		cache                  *evalCache
		exposureAnalysisFlag   bool
		representativePeersMap map[string]*k8s.WorkloadPeer // map from unique labels string to representative peer object,
		// used only with exposure analysis (representative peer object is a workloadPeer with kind == "RepresentativePeer")
	}

	// NotificationTarget defines an interface for updating the state needed for network policy
	// decisions
	NotificationTarget interface {
		// InsertObject inserts (or updates) an object to the policy engine's view of the world
		InsertObject(obj runtime.Object) error
		// DeleteObject removes an object from the policy engine's view of the world
		DeleteObject(obj runtime.Object) error
	}
)

// NewPolicyEngine returns a new PolicyEngine with an empty initial state
func NewPolicyEngine(l logger.Logger) *PolicyEngine {
	return &PolicyEngine{
		logger:                          l,
		namespacesMap:                   make(map[string]*k8s.Namespace),
		podsMap:                         make(map[string]*k8s.Pod),
		netpolsMap:                      make(map[string]map[string]*k8s.NetworkPolicy),
		podOwnersToRepresentativePodMap: make(map[string]map[string]*k8s.Pod),
		adminNetpolsMap:                 make(map[string]bool),
		cache:                           newEvalCache(),
		exposureAnalysisFlag:            false,
	}
}

func NewPolicyEngineWithObjects(objects []parser.K8sObject, l logger.Logger) (*PolicyEngine, error) {
	pe := NewPolicyEngine(l)
	err := pe.addObjectsByKind(objects)
	return pe, err
}

// NewPolicyEngineWithOptions returns a new policy engine with an empty state but updating the exposure analysis flag
// TBD: currently exposure-analysis is the only option supported by policy-engine, so no need for options list param
func NewPolicyEngineWithOptions(exposureFlag bool, l logger.Logger) *PolicyEngine {
	pe := NewPolicyEngine(l)
	pe.exposureAnalysisFlag = exposureFlag
	if exposureFlag {
		pe.representativePeersMap = make(map[string]*k8s.WorkloadPeer)
	}
	return pe
}

// AddObjectsForExposureAnalysis adds k8s objects to the policy engine: first adds network-policies and namespaces and then other objects.
// for exposure analysis we need to insert first policies and namespaces so:
// 1. policies: so a representative peer for each policy rule is added
// 2. namespaces: so when inserting workloads, we'll be able to check correctly if a generated representative peer
// should be removed, i.e. its labels and namespace correspond to a real pod.
// i.e. when inserting a new real workload/pod, all real namespaces will be already inserted for sure and the
// real labels will be considered correctly when looping the representative peers.
// this func is called only for exposure analysis; otherwise does nothing
func (pe *PolicyEngine) AddObjectsForExposureAnalysis(objects []parser.K8sObject) error {
	if !pe.exposureAnalysisFlag { // should not be true ever
		return nil
	}
	policiesAndNamespaces, otherObjects := splitPoliciesAndNamespacesAndOtherObjects(objects)
	// note: in the first call addObjectsByKind with policy objects, will add
	// the representative peers
	err := pe.addObjectsByKind(policiesAndNamespaces)
	if err != nil {
		return err
	}
	// note: in the second call addObjectsByKind with workload objects, will possibly remove some
	// representative peers (for which there is already an identical actual workload with simple selectors)
	err = pe.addObjectsByKind(otherObjects)
	return err
}

func splitPoliciesAndNamespacesAndOtherObjects(objects []parser.K8sObject) (policiesAndNs, others []parser.K8sObject) {
	for i := range objects {
		obj := objects[i]
		switch obj.Kind {
		// @todo : when enabling exposure-analysis with projects containing admin netpols:
		// consider also parser.AdminNetorkPolicy and parser.BaselineAdminNetworkPolicy
		case parser.NetworkPolicy:
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
//
//gocyclo:ignore
func (pe *PolicyEngine) addObjectsByKind(objects []parser.K8sObject) error {
	var err error
	for i := range objects {
		obj := objects[i]
		switch obj.Kind {
		case parser.Namespace:
			err = pe.InsertObject(obj.Namespace)
		case parser.NetworkPolicy:
			err = pe.InsertObject(obj.NetworkPolicy)
		case parser.Pod:
			err = pe.InsertObject(obj.Pod)
		case parser.ReplicaSet:
			err = pe.InsertObject(obj.ReplicaSet)
		case parser.Deployment:
			err = pe.InsertObject(obj.Deployment)
		case parser.DaemonSet:
			err = pe.InsertObject(obj.DaemonSet)
		case parser.StatefulSet:
			err = pe.InsertObject(obj.StatefulSet)
		case parser.ReplicationController:
			err = pe.InsertObject(obj.ReplicationController)
		case parser.Job:
			err = pe.InsertObject(obj.Job)
		case parser.CronJob:
			err = pe.InsertObject(obj.CronJob)
		case parser.AdminNetworkPolicy:
			err = pe.InsertObject(obj.AdminNetworkPolicy)
		case parser.BaselineAdminNetworkPolicy:
			err = pe.InsertObject(obj.BaselineAdminNetworkPolicy)
		case parser.Service, parser.Route, parser.Ingress:
			continue
		default:
			fmt.Printf("ignoring resource kind %s", obj.Kind)
		}
		if err != nil {
			return err
		}
	}
	if !pe.exposureAnalysisFlag {
		// @todo: put following line outside the if statement when exposure analysis is supported with (B)ANPs
		if err := pe.sortAdminNetpolsByPriority(); err != nil {
			return err
		}
		return pe.resolveMissingNamespaces() // for exposure analysis; this already done
	}
	return nil
}

// sortAdminNetpolsByPriority sorts all input admin-netpols by their priority;
// since the priority of policies is critical for computing the conns between peers
func (pe *PolicyEngine) sortAdminNetpolsByPriority() error {
	var err error
	sort.Slice(pe.sortedAdminNetpols, func(i, j int) bool {
		// outcome is non-deterministic if there are two AdminNetworkPolicies at the same priority
		if pe.sortedAdminNetpols[i].Spec.Priority == pe.sortedAdminNetpols[j].Spec.Priority {
			err = errors.New(netpolerrors.SamePriorityErr(pe.sortedAdminNetpols[i].Name, pe.sortedAdminNetpols[j].Name))
			return false
		}
		// priority values range is defined
		if !pe.sortedAdminNetpols[i].HasValidPriority() {
			err = errors.New(netpolerrors.PriorityValueErr(pe.sortedAdminNetpols[i].Name, pe.sortedAdminNetpols[i].Spec.Priority))
			return false
		}
		if !pe.sortedAdminNetpols[j].HasValidPriority() {
			err = errors.New(netpolerrors.PriorityValueErr(pe.sortedAdminNetpols[j].Name, pe.sortedAdminNetpols[j].Spec.Priority))
			return false
		}
		return pe.sortedAdminNetpols[i].Spec.Priority < pe.sortedAdminNetpols[j].Spec.Priority
	})
	return err
}

func (pe *PolicyEngine) resolveMissingNamespaces() error {
	for _, pod := range pe.podsMap {
		ns := pod.Namespace
		if err := pe.resolveSingleMissingNamespace(ns); err != nil {
			return err
		}
	}
	return nil
}

// defaultNamespaceLabelsMap returns a map with a single key: val for the default K8s namespace name key.
func defaultNamespaceLabelsMap(namespaceName string) map[string]string {
	return map[string]string{common.K8sNsNameLabelKey: namespaceName}
}

// resolveSingleMissingNamespace for missing ns: create a ns object and insert to PolicyEngine
func (pe *PolicyEngine) resolveSingleMissingNamespace(ns string) error {
	if _, ok := pe.namespacesMap[ns]; ok {
		return nil // namespace is not missing - do nothing
	}
	nsObj := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   ns,
			Labels: defaultNamespaceLabelsMap(ns),
		},
	}
	if err := pe.insertNamespace(nsObj); err != nil {
		return err
	}
	return nil
}

// SetResources: updates the set of all relevant k8s resources
// This function *may* be used as convenience to set the initial policy engine state from a
// set of resources (e.g., retrieved via List from a cluster).
//
// Deprecated: this function simply calls InsertObject on the PolicyEngine.
// Calling the InsertObject should be preferred in new code.
func (pe *PolicyEngine) SetResources(policies []*netv1.NetworkPolicy, pods []*corev1.Pod,
	namespaces []*corev1.Namespace) error {
	for i := range namespaces {
		if err := pe.insertNamespace(namespaces[i]); err != nil {
			return err
		}
	}
	for i := range policies {
		if err := pe.insertNetworkPolicy(policies[i]); err != nil {
			return err
		}
	}
	for i := range pods {
		if err := pe.insertPod(pods[i]); err != nil {
			return err
		}
	}

	return nil
}

// InsertObject updates (an existing) or inserts (a new) object in the PolicyEngine's
// view of the world
func (pe *PolicyEngine) InsertObject(rtObj runtime.Object) error {
	switch obj := rtObj.(type) {
	// namespace object
	case *corev1.Namespace:
		return pe.insertNamespace(obj)
	// pod object
	case *corev1.Pod:
		return pe.insertPod(obj)
	// netpol object
	case *netv1.NetworkPolicy:
		return pe.insertNetworkPolicy(obj)
	// workload object
	case *appsv1.ReplicaSet:
		return pe.insertWorkload(obj, parser.ReplicaSet)
	case *appsv1.Deployment:
		return pe.insertWorkload(obj, parser.Deployment)
	case *appsv1.StatefulSet:
		return pe.insertWorkload(obj, parser.StatefulSet)
	case *appsv1.DaemonSet:
		return pe.insertWorkload(obj, parser.DaemonSet)
	case *corev1.ReplicationController:
		return pe.insertWorkload(obj, parser.ReplicationController)
	case *batchv1.CronJob:
		return pe.insertWorkload(obj, parser.CronJob)
	case *batchv1.Job:
		return pe.insertWorkload(obj, parser.Job)
	case *apisv1a.AdminNetworkPolicy:
		return pe.insertAdminNetworkPolicy(obj)
	case *apisv1a.BaselineAdminNetworkPolicy:
		return pe.insertBaselineAdminNetworkPolicy(obj)
	}
	return nil
}

// DeleteObject removes an object from the PolicyEngine's view of the world
func (pe *PolicyEngine) DeleteObject(rtObj runtime.Object) error {
	switch obj := rtObj.(type) {
	case *corev1.Namespace:
		return pe.deleteNamespace(obj)
	case *corev1.Pod:
		return pe.deletePod(obj)
	case *netv1.NetworkPolicy:
		return pe.deleteNetworkPolicy(obj)
	case *apisv1a.AdminNetworkPolicy:
		return pe.deleteAdminNetworkPolicy(obj)
	case *apisv1a.BaselineAdminNetworkPolicy:
		return pe.deleteBaselineAdminNetworkPolicy(obj)
	}
	return nil
}

// ClearResources: deletes all current k8s resources
func (pe *PolicyEngine) ClearResources() {
	pe.namespacesMap = make(map[string]*k8s.Namespace)
	pe.podsMap = make(map[string]*k8s.Pod)
	pe.netpolsMap = make(map[string]map[string]*k8s.NetworkPolicy)
	pe.podOwnersToRepresentativePodMap = make(map[string]map[string]*k8s.Pod)
	if pe.exposureAnalysisFlag {
		pe.representativePeersMap = make(map[string]*k8s.WorkloadPeer)
	}
	pe.cache = newEvalCache()
	pe.adminNetpolsMap = make(map[string]bool)
	pe.sortedAdminNetpols = make([]*k8s.AdminNetworkPolicy, 0)
	pe.baselineAdminNetpol = nil
}

func (pe *PolicyEngine) insertNamespace(ns *corev1.Namespace) error {
	nsObj, err := k8s.NamespaceFromCoreObject(ns)
	if err != nil {
		return err
	}
	pe.namespacesMap[nsObj.Name] = nsObj
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

func (pe *PolicyEngine) insertWorkload(rs interface{}, kind string) error {
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
		err = pe.removeRedundantRepresentativePeers(podObj)
	}
	return err
}

func (pe *PolicyEngine) insertPod(pod *corev1.Pod) error {
	podObj, err := k8s.PodFromCoreObject(pod)
	if err != nil {
		return err
	}
	podStr := types.NamespacedName{Namespace: podObj.Namespace, Name: podObj.Name}
	pe.podsMap[podStr.String()] = podObj
	// update cache with new pod associated to to its owner
	pe.cache.addPod(podObj, podStr.String())
	if pe.exposureAnalysisFlag {
		err = pe.removeRedundantRepresentativePeers(podObj)
	}
	return err
}

func initPolicyExposureWithoutSelectors() k8s.PolicyExposureWithoutSelectors {
	return k8s.PolicyExposureWithoutSelectors{
		ExternalExposure:    common.MakeConnectionSet(false),
		ClusterWideExposure: common.MakeConnectionSet(false),
	}
}

func (pe *PolicyEngine) insertNetworkPolicy(np *netv1.NetworkPolicy) error {
	netpolNamespace := np.ObjectMeta.Namespace
	if netpolNamespace == "" {
		netpolNamespace = metav1.NamespaceDefault
		np.ObjectMeta.Namespace = netpolNamespace
	}
	if _, ok := pe.netpolsMap[netpolNamespace]; !ok {
		pe.netpolsMap[netpolNamespace] = make(map[string]*k8s.NetworkPolicy)
	}

	newNetpol := &k8s.NetworkPolicy{
		NetworkPolicy:         np,
		IngressPolicyExposure: initPolicyExposureWithoutSelectors(),
		EgressPolicyExposure:  initPolicyExposureWithoutSelectors(),
		Logger:                pe.logger,
	}
	if _, ok := pe.netpolsMap[netpolNamespace][np.Name]; ok {
		return errors.New(netpolerrors.NPWithSameNameError(types.NamespacedName{Namespace: netpolNamespace, Name: np.Name}.String()))
	}
	pe.netpolsMap[netpolNamespace][np.Name] = newNetpol

	var err error
	// for exposure analysis only: scan policy ingress and egress rules:
	// 1. to store allowed connections to entire cluster and to external destinations (if such connections are allowed by the policy)
	// 2. to get selectors and generate representativePeers
	if pe.exposureAnalysisFlag {
		rulesSelectors, scanErr := newNetpol.GetPolicyRulesSelectorsAndUpdateExposureClusterWideConns()
		if scanErr != nil {
			return scanErr
		}
		err = pe.generateRepresentativePeers(rulesSelectors, np.Namespace)
	}
	// clear the cache on netpols changes
	pe.cache.clear()
	return err
}

func (pe *PolicyEngine) insertAdminNetworkPolicy(anp *apisv1a.AdminNetworkPolicy) error {
	// @TBD : currently disabling exposure-analysis when there are admin-network-policies in the input resources
	if pe.exposureAnalysisFlag {
		return errors.New(netpolerrors.ExposureAnalysisDisabledWithANPs)
	}
	if pe.adminNetpolsMap[anp.Name] {
		return errors.New(netpolerrors.ANPsWithSameNameErr(anp.Name))
	}
	newAnp := &k8s.AdminNetworkPolicy{
		AdminNetworkPolicy: anp,
		Logger:             pe.logger,
	}
	pe.adminNetpolsMap[anp.Name] = true
	pe.sortedAdminNetpols = append(pe.sortedAdminNetpols, newAnp)
	return nil
}

func (pe *PolicyEngine) insertBaselineAdminNetworkPolicy(banp *apisv1a.BaselineAdminNetworkPolicy) error {
	// @TBD : currently disabling exposure-analysis when there are (baseline)-admin-network-policies in the input resources
	if pe.exposureAnalysisFlag {
		return errors.New(netpolerrors.ExposureAnalysisDisabledWithANPs)
	}
	if pe.baselineAdminNetpol != nil { // @todo : should this be a warning? the last banp the one considered
		return errors.New(netpolerrors.BANPAlreadyExists)
	}
	if banp.Name != "default" { // "You must use default as the name when creating a BaselineAdminNetworkPolicy object."
		// see https://www.redhat.com/en/blog/using-adminnetworkpolicy-api-to-secure-openshift-cluster-networking
		// or this: https://pkg.go.dev/sigs.k8s.io/network-policy-api@v0.1.5/apis/v1alpha1#BaselineAdminNetworkPolicy
		return errors.New(netpolerrors.BANPNameAssertion)
	}
	newBanp := &k8s.BaselineAdminNetworkPolicy{
		BaselineAdminNetworkPolicy: banp,
		Logger:                     pe.logger,
	}
	pe.baselineAdminNetpol = newBanp
	return nil
}

func (pe *PolicyEngine) deleteNamespace(ns *corev1.Namespace) error {
	delete(pe.namespacesMap, ns.Name)
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

func (pe *PolicyEngine) deleteAdminNetworkPolicy(anp *apisv1a.AdminNetworkPolicy) error {
	delete(pe.adminNetpolsMap, anp.Name)
	// delete anp from the pe.sortedAdminNetpols list
	for i, item := range pe.sortedAdminNetpols {
		if item.AdminNetworkPolicy == anp {
			// assign to pe.sortedAdminNetpols all ANPs except for current item
			pe.sortedAdminNetpols = append(pe.sortedAdminNetpols[:i], pe.sortedAdminNetpols[i+1:]...)
			break
		}
	}
	return nil
}

func (pe *PolicyEngine) deleteBaselineAdminNetworkPolicy(banp *apisv1a.BaselineAdminNetworkPolicy) error {
	if pe.baselineAdminNetpol.Name == banp.Name { // if this is the banp used in pe delete it
		// @TBD : should keep this if? no other banps are in the resources (illegal)
		pe.baselineAdminNetpol = nil
	}
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

// getDisjointIPBlocks returns a slice of disjoint ip-blocks from all policy resources
func (pe *PolicyEngine) getDisjointIPBlocks() ([]*netset.IPBlock, error) {
	ipbList, err := pe.getDisjointIPBlocksFromNetpols()
	if err != nil {
		return nil, err
	}
	anpIpbList, err := pe.getDisjointIPBlocksFromAdminNetpols()
	if err != nil {
		return nil, err
	}
	ipbList = append(ipbList, anpIpbList...)
	if pe.baselineAdminNetpol != nil {
		banpIPList, err := pe.baselineAdminNetpol.GetReferencedIPBlocks()
		if err != nil {
			return nil, err
		}
		ipbList = append(ipbList, banpIPList...)
	}
	newAll := netset.GetCidrAll()
	disjointRes := netset.DisjointIPBlocks(ipbList, []*netset.IPBlock{newAll})
	return disjointRes, nil
}

// getDisjointIPBlocksFromNetpols returns a slice of disjoint ip-blocks from all netpols
// (NetworkPolicy objects)
func (pe *PolicyEngine) getDisjointIPBlocksFromNetpols() ([]*netset.IPBlock, error) {
	var ipbList []*netset.IPBlock
	for _, nsMap := range pe.netpolsMap {
		for _, policy := range nsMap {
			policyIPBlocksList, err := policy.GetReferencedIPBlocks()
			if err != nil {
				return nil, err
			}
			ipbList = append(ipbList, policyIPBlocksList...)
		}
	}
	return ipbList, nil
}

// getDisjointIPBlocksFromAdminNetpols returns a slice of disjoint IPBlocks from all admin netpols
// (AdminNetworkPolicy objects)
func (pe *PolicyEngine) getDisjointIPBlocksFromAdminNetpols() ([]*netset.IPBlock, error) {
	var ipbList []*netset.IPBlock
	for _, anp := range pe.sortedAdminNetpols {
		anpIPBlocksList, err := anp.GetReferencedIPBlocks()
		if err != nil {
			return nil, err
		}
		ipbList = append(ipbList, anpIPBlocksList...)
	}
	return ipbList, nil
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
func (pe *PolicyEngine) ConvertPeerNamedPort(namedPort string, peer Peer) (protocol string, portNum int32, err error) {
	switch currentPeer := peer.(type) {
	case *k8s.WorkloadPeer:
		protocol, portNum := currentPeer.Pod.ConvertPodNamedPort(namedPort)
		return protocol, portNum, nil
	case *k8s.PodPeer:
		protocol, portNum := currentPeer.Pod.ConvertPodNamedPort(namedPort)
		return protocol, portNum, nil
	default:
		return "", 0, errors.New("peer type does not have ports") // should not get here
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

// addRepresentativePod adds a new representative pod to the policy-engine (to pe.representativePeersMap).
// if the given namespace string (podNs) is not empty (i.e. a real (policy's) namespace name), it will be assigned to the pod's Namespace;
// and the "namespace name" requirement of the representative pod will be stored in its RepresentativeNsLabelSelector field.
// Otherwise, the representative pod will have no namespace (will not add a representative namespace to the policy-engine).
// this func is used only with exposure-analysis
func (pe *PolicyEngine) addRepresentativePod(podNs string, objSelectors *k8s.SingleRuleSelectors) error {
	if objSelectors == nil { // should not get here
		return errors.New(netpolerrors.NilRepresentativePodSelectorsErr)
	}
	nsLabelSelector := objSelectors.NsSelector
	if nsLabelSelector == nil && podNs == "" { // should not get here as nsLabelSelector == nil should be equivalent to podNs not empty
		return errors.New(netpolerrors.NilNamespaceAndNilNsSelectorErr)
	}
	if nsLabelSelector == nil && podNs != "" {
		// if the objSelectors.NsSelector is nil, means inferred from a rule with nil nsSelector, which means the namespace of the
		// pod is the namespace of the policy, so adding it as its RepresentativeNsLabelSelector requirement.
		// by this, we ensure a representative peer may only represent the rule it was inferred from
		// and uniqueness of representative peers.
		// (another policy in another namespace, may have a rule with same podSelector, but the namespace will be different-
		// so a different representative peer will be generated)
		nsLabelSelector = &metav1.LabelSelector{MatchLabels: defaultNamespaceLabelsMap(podNs)}
	}
	newPod := &k8s.Pod{
		// all representative pods are having same name since this name is used only to indicate that this Fake Pod is representative;
		// this name is not used for storing it in the policy-engine/ comparing with other peers/ or representing it.
		Name:                           k8s.RepresentativePodName,
		Namespace:                      podNs,
		FakePod:                        true,
		RepresentativePodLabelSelector: objSelectors.PodSelector,
		RepresentativeNsLabelSelector:  nsLabelSelector,
	}
	//  compute a unique string from the label selectors to be used as the map key
	// note that nsLabelSelector will not be nil
	nsKey, err := k8s.UniqueKeyFromLabelsSelector(nsLabelSelector)
	if err != nil {
		return err
	}
	podKey, err := k8s.UniqueKeyFromLabelsSelector(objSelectors.PodSelector)
	if err != nil {
		return err
	}
	keyStrFromLabels := nsKey + "/" + podKey
	if _, ok := pe.representativePeersMap[keyStrFromLabels]; ok { // we already have a representative peer with same labels
		return nil
	}
	// create a new representative peer
	newRepresentativePeer := &k8s.WorkloadPeer{Pod: newPod}
	// add the new representative peer to the policy-engine
	pe.representativePeersMap[keyStrFromLabels] = newRepresentativePeer
	return nil
}
