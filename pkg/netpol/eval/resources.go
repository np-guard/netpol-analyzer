/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package eval

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	apisv1a "sigs.k8s.io/network-policy-api/apis/v1alpha1"
	policyapi "sigs.k8s.io/network-policy-api/pkg/client/clientset/versioned"

	"github.com/np-guard/models/pkg/netset"

	pkgcommon "github.com/np-guard/netpol-analyzer/pkg/internal/common"
	"github.com/np-guard/netpol-analyzer/pkg/logger"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/parser"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval/internal/k8s"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/alerts"
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
		explain                bool
		representativePeersMap map[string]*k8s.WorkloadPeer // map from unique labels string to representative peer object,
		// used only with exposure analysis (representative peer object is a workloadPeer with kind == "RepresentativePeer")
		objectsList []parser.K8sObject // list of k8s objects to be inserted to the policy-engine
	}

	// NotificationTarget defines an interface for updating the state needed for network policy
	// decisions
	NotificationTarget interface {
		// InsertObject inserts (or updates) an object to the policy engine's view of the world
		InsertObject(obj runtime.Object) error
		// DeleteObject removes an object from the policy engine's view of the world
		DeleteObject(obj runtime.Object) error
	}

	// PolicyEngineOption is the type for specifying options for PolicyEngine,
	// using Golang's Options Pattern (https://golang.cafe/blog/golang-functional-options-pattern.html).
	PolicyEngineOption func(*PolicyEngine)
)

// WithLogger is a functional option which sets the logger for a PolicyEngine to use.
// The provided logger must conform with the package's Logger interface.
func WithLogger(l logger.Logger) PolicyEngineOption {
	return func(pe *PolicyEngine) {
		pe.logger = l
	}
}

// WithExplanation is a functional option which directs PolicyEngine whether to perform explainability analysis
func WithExplanation(explain bool) PolicyEngineOption {
	return func(pe *PolicyEngine) {
		pe.explain = explain
	}
}

// WithExposureAnalysis is a functional option which directs PolicyEngine to perform exposure analysis
func WithExposureAnalysis() PolicyEngineOption {
	return func(pe *PolicyEngine) {
		pe.exposureAnalysisFlag = true
		pe.representativePeersMap = make(map[string]*k8s.WorkloadPeer)
	}
}

// WithObjectsList is a functional option which directs the policyEngine to insert given k8s objects by kind
func WithObjectsList(objects []parser.K8sObject) PolicyEngineOption {
	return func(pe *PolicyEngine) {
		pe.objectsList = objects
	}
}

// NewPolicyEngine returns a new PolicyEngine with an empty initial state
func NewPolicyEngine() *PolicyEngine {
	return &PolicyEngine{
		namespacesMap:                   make(map[string]*k8s.Namespace),
		podsMap:                         make(map[string]*k8s.Pod),
		netpolsMap:                      make(map[string]map[string]*k8s.NetworkPolicy),
		podOwnersToRepresentativePodMap: make(map[string]map[string]*k8s.Pod),
		adminNetpolsMap:                 make(map[string]bool),
		cache:                           newEvalCache(),
		exposureAnalysisFlag:            false,
		explain:                         false,
		logger:                          logger.NewDefaultLogger(),
	}
}

// Deprecated : this func call is contained in NewPolicyEngineWithOptionsList
func NewPolicyEngineWithObjects(objects []parser.K8sObject) (*PolicyEngine, error) {
	pe := NewPolicyEngine()
	err := pe.addObjectsByKind(objects)
	return pe, err
}

// NewPolicyEngineWithOptions returns a new policy engine with an empty state but updating the exposure analysis flag
// Deprecated: this function is implemented also within NewPolicyEngineWithOptionsList
func NewPolicyEngineWithOptions(exposureFlag bool) *PolicyEngine {
	pe := NewPolicyEngine()
	pe.exposureAnalysisFlag = exposureFlag
	if exposureFlag {
		pe.representativePeersMap = make(map[string]*k8s.WorkloadPeer)
	}
	return pe
}

// NewPolicyEngineWithOptionsList returns a new policy engine with given options
func NewPolicyEngineWithOptionsList(opts ...PolicyEngineOption) (pe *PolicyEngine, err error) {
	pe = NewPolicyEngine()
	for _, o := range opts {
		o(pe)
	}
	// if objects list is not empty insert objects by kind and considering exposure-analysis flag
	if len(pe.objectsList) > 0 {
		if pe.exposureAnalysisFlag {
			err = pe.addObjectsForExposureAnalysis()
		} else {
			err = pe.addObjectsByKind(pe.objectsList)
		}
	}
	return pe, err
}

// addObjectsForExposureAnalysis adds pe's k8s objects: first adds policies (NetworkPolicy, AdminNetworkPolicy
// and BaselineAdminNetworkPolicy objects) and namespaces and then other objects.
// for exposure analysis we need to insert first policies and namespaces so:
// 1. policies: so a representative peer for each policy rule is added
// 2. namespaces: so when inserting workloads, we'll be able to check correctly if a generated representative peer
// should be removed, i.e. its labels and namespace correspond to a real pod.
// i.e. when inserting a new real workload/pod, all real namespaces will be already inserted for sure and the
// real labels will be considered correctly when looping the representative peers.
// this func is called only for exposure analysis; otherwise does nothing
func (pe *PolicyEngine) addObjectsForExposureAnalysis() error {
	if !pe.exposureAnalysisFlag { // should not be true ever
		return nil
	}
	policiesAndNamespaces, otherObjects := splitPoliciesAndNamespacesAndOtherObjects(pe.objectsList)
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
		case parser.NetworkPolicy:
			policiesAndNs = append(policiesAndNs, obj)
		case parser.AdminNetworkPolicy:
			policiesAndNs = append(policiesAndNs, obj)
		case parser.BaselineAdminNetworkPolicy:
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
	if err := pe.sortAdminNetpolsByPriority(); err != nil {
		return err
	}
	if !pe.exposureAnalysisFlag {
		return pe.resolveMissingNamespaces() // for exposure analysis; this already done
	}
	return nil
}

// sortAdminNetpolsByPriority sorts all input admin-netpols by their priority;
// since the priority of policies is critical for computing the conns between peers
func (pe *PolicyEngine) sortAdminNetpolsByPriority() error {
	var err error
	if len(pe.sortedAdminNetpols) == 1 && !pe.sortedAdminNetpols[0].HasValidPriority() {
		return errors.New(alerts.PriorityValueErr(pe.sortedAdminNetpols[0].Name, pe.sortedAdminNetpols[0].Spec.Priority))
	}
	sort.Slice(pe.sortedAdminNetpols, func(i, j int) bool {
		// outcome is non-deterministic if there are two AdminNetworkPolicies at the same priority
		if pe.sortedAdminNetpols[i].Spec.Priority == pe.sortedAdminNetpols[j].Spec.Priority {
			err = errors.New(alerts.SamePriorityErr(pe.sortedAdminNetpols[i].Name, pe.sortedAdminNetpols[j].Name))
			return false
		}
		// priority values range is defined
		if !pe.sortedAdminNetpols[i].HasValidPriority() {
			err = errors.New(alerts.PriorityValueErr(pe.sortedAdminNetpols[i].Name, pe.sortedAdminNetpols[i].Spec.Priority))
			return false
		}
		if !pe.sortedAdminNetpols[j].HasValidPriority() {
			err = errors.New(alerts.PriorityValueErr(pe.sortedAdminNetpols[j].Name, pe.sortedAdminNetpols[j].Spec.Priority))
			return false
		}
		return pe.sortedAdminNetpols[i].Spec.Priority < pe.sortedAdminNetpols[j].Spec.Priority
	})
	return err
}

// UpdatePolicyEngineWithK8sPolicyAPIObjects inserts to the policy-engine all (baseline)admin network policies
func (pe *PolicyEngine) UpdatePolicyEngineWithK8sPolicyAPIObjects(clientset policyapi.Interface) error {
	ctx, cancel := context.WithTimeout(context.Background(), pkgcommon.CtxTimeoutSeconds*time.Second)
	defer cancel()
	// get all admin-network-policies
	anpList, apiErr := clientset.PolicyV1alpha1().AdminNetworkPolicies().List(ctx, metav1.ListOptions{})
	if apiErr != nil {
		// if the apiErr is of type "apierrors.IsNotFound";
		// it means the api server could not find the requested resource (get adminnetworkpolicies.policy.networking.k8s.io); i.e. the
		// cluster does not support this type of object (network-policy-api objects)
		if apierrors.IsNotFound(apiErr) {
			pe.logger.Debugf(alerts.K8sClusterDoesNotSupportNetworkPolicyAPI)
			return nil // don't proceed this client is not used
		}
		return apiErr
	}
	for i := range anpList.Items {
		if err := pe.InsertObject(&anpList.Items[i]); err != nil {
			return err
		}
	}
	// sort the admin-netpols by the priority - since their priority ordering is critic for computing allowed conns
	err := pe.sortAdminNetpolsByPriority()
	if err != nil {
		return err
	}
	// get baseline-admin-netpol
	banpList, apiErr := clientset.PolicyV1alpha1().BaselineAdminNetworkPolicies().List(ctx, metav1.ListOptions{})
	if apiErr != nil {
		if apierrors.IsNotFound(apiErr) { // even though it would not be reached; since if banp is not
			// supported by the cluster; ANPs would not be supported too
			pe.logger.Debugf(alerts.K8sClusterDoesNotSupportNetworkPolicyAPI)
			return nil
		}
		return apiErr
	}
	for i := range banpList.Items {
		if err := pe.InsertObject(&banpList.Items[i]); err != nil {
			return err
		}
	}
	return nil
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

// checkConsistentLabelsForPodsOfSameOwner returns error if:
// there are pod resources with same ownerReferences name but different labels (labels gap) and there is a policy selector or
// policy-rule selector which selects the pods with a label from the gap
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

	// if there are no policies in the policy-engine then labels diffs do not affect connectivity results - return
	if !pe.hasPolicies() {
		return nil
	}
	// @todo: as enhancement may compare selectors with gap-labels on the flow of computing the allowed-conns,
	// then generating the error would be moved

	// compare the owner first pod's labels with new pod's Labels;
	// if there is a diff between labels which may affect the connectivity results (labels from the gap used by policies);
	// then return an error with first captured different label's values
	if gapData := pe.diffBetweenPodsLabelsAffectConnectivity(firstPod, newPod); gapData.key != "" {
		return generateLabelsDiffError(firstPod, newPod, gapData) // err
	}
	return nil
}

func (pe *PolicyEngine) hasPolicies() bool {
	return len(pe.netpolsMap) > 0 || len(pe.sortedAdminNetpols) > 0 || pe.baselineAdminNetpol != nil
}

// labelsDiffData contains data of the first captured label from the gap-labels which is selected by a policy
type labelsDiffData struct {
	key               string
	firstVal          string
	secondVal         string
	policyStr         string
	policySelectorStr string
}

// helper: generateLabelsDiffError generates the error message of the gap between two pods' labels
func generateLabelsDiffError(firstPod, newPod *k8s.Pod, gapData *labelsDiffData) error {
	// helping vars declarations to avoid duplicates
	ownerName := types.NamespacedName{Namespace: firstPod.Namespace, Name: firstPod.Owner.Name}.String()
	newPodStr := types.NamespacedName{Namespace: newPod.Namespace, Name: newPod.Name}.String()
	firstPodStr := types.NamespacedName{Namespace: firstPod.Namespace, Name: firstPod.Name}.String()
	errMsgPart1 := alerts.NotSupportedPodResourcesErrorStr(ownerName)
	errMsgPart2 := ""
	keyMissingErr := "Pod %q has label `%s=%s`, and Pod %q does not have label `%s`,"
	differentValuesErr := "Pod %q has label `%s=%s`, and Pod %q has label `%s=%s`,"
	policyValuesErr := fmt.Sprintf(" while %s contains selector `%s`", gapData.policyStr, gapData.policySelectorStr)
	switch {
	case gapData.firstVal == "":
		errMsgPart2 = fmt.Sprintf(keyMissingErr, newPodStr, gapData.key, gapData.secondVal, firstPodStr, gapData.key)
	case gapData.secondVal == "":
		errMsgPart2 = fmt.Sprintf(keyMissingErr, firstPodStr, gapData.key, gapData.firstVal, newPodStr, gapData.key)
	default: // both values are not empty
		errMsgPart2 = fmt.Sprintf(differentValuesErr, newPodStr, gapData.key, gapData.secondVal, firstPodStr, gapData.key, gapData.firstVal)
	}
	return errors.New(errMsgPart1 + errMsgPart2 + policyValuesErr)
}

// helper: given two pods of same owner, if there are diffs between the pods' labels maps returns first captured diff components,
// i.e. the different label's key and the different values / empty val if the key is missing in one pod's labels
// with the strings of policy and selector which uses that label;
// if there is no diff/ diff labels are not selected by any policy-selector, returns empty key (with empty values)
func (pe *PolicyEngine) diffBetweenPodsLabelsAffectConnectivity(firstPod, newPod *k8s.Pod) (gapData *labelsDiffData) {
	// try to find diffs by looping new pod's labels first
	differentLabels := map[string][]string{} // map from key to its values in the two pods
	for key, value := range newPod.Labels {
		if _, ok := firstPod.Labels[key]; !ok { // newPod has a key which does not exist in the firstPod
			differentLabels[key] = []string{"", value}
		}
		if firstPod.Labels[key] != value { // the values of the label key are not equal
			differentLabels[key] = []string{firstPod.Labels[key], value}
		}
	}
	// check if first pod's labels contains keys which are not in the new pod's labels
	for key, val := range firstPod.Labels {
		if _, ok := newPod.Labels[key]; !ok {
			differentLabels[key] = []string{val, ""}
		}
	}
	// following func is called only in case there are policies in the policy engine and there is a pod-owner with pods with labels gap
	// however, it is possible to implement this in another way,
	// @todo - in order to enhance performance; instead of checking if the policies use the different labels here, add "differentLabels" map
	// (with more data on the owner and pods) as a policy-engine attribute.
	// and while looping policies for computing allowed conns between peers, do this check (pass the pe.differentLabels to those funcs)
	if len(differentLabels) > 0 {
		return pe.checkIfDifferentLabelsUsedByPolicy(firstPod.Namespace, differentLabels)
	}
	return &labelsDiffData{}
}

// checkIfDifferentLabelsUsedByPolicy loops the policies and checks if any of the policies' selectors contains
// a key label from the input differentLabels map
// if a policy selector contains such <key:val> label or a match expression that may cause an ambiguity on selecting the
// correct pods (where the pods has same owner but labels with same key and different values)
// the connectivity analysis is not supported for input resources.
func (pe *PolicyEngine) checkIfDifferentLabelsUsedByPolicy(ownerNs string,
	differentLabels map[string][]string) (gapData *labelsDiffData) {
	// check if different labels are selected by the policies and may affect the analysis results
	for ns := range pe.netpolsMap {
		for _, np := range pe.netpolsMap[ns] {
			if key, selectorStr := np.ContainsLabels(pe.namespacesMap[ownerNs], differentLabels); key != "" {
				return &labelsDiffData{key: key, firstVal: differentLabels[key][0], secondVal: differentLabels[key][1],
					policyStr:         fmt.Sprintf("NetworkPolicy: %q", types.NamespacedName{Name: np.Name, Namespace: np.Namespace}.String()),
					policySelectorStr: selectorStr}
			}
		}
	}
	// check on admin-netpols
	for _, anp := range pe.sortedAdminNetpols {
		if key, selectorStr := anp.ContainsLabels(pe.namespacesMap[ownerNs], differentLabels); key != "" {
			return &labelsDiffData{key: key, firstVal: differentLabels[key][0], secondVal: differentLabels[key][1],
				policyStr:         fmt.Sprintf("AdminNetworkPolicy: %q", anp.Name),
				policySelectorStr: selectorStr}
		}
	}
	// check the baselineAdminNetpol
	if pe.baselineAdminNetpol != nil {
		if key, selectorStr := pe.baselineAdminNetpol.ContainsLabels(pe.namespacesMap[ownerNs], differentLabels); key != "" {
			return &labelsDiffData{key: key, firstVal: differentLabels[key][0], secondVal: differentLabels[key][1],
				policyStr:         fmt.Sprintf("BaselineAdminNetworkPolicy: %q", pe.baselineAdminNetpol.Name),
				policySelectorStr: selectorStr}
		}
	}
	return &labelsDiffData{}
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

func (pe *PolicyEngine) insertNetworkPolicy(np *netv1.NetworkPolicy) error {
	netpolNamespace := np.Namespace
	if netpolNamespace == "" {
		netpolNamespace = metav1.NamespaceDefault
		np.Namespace = netpolNamespace
	}
	if _, ok := pe.netpolsMap[netpolNamespace]; !ok {
		pe.netpolsMap[netpolNamespace] = make(map[string]*k8s.NetworkPolicy)
	}

	newNetpol := &k8s.NetworkPolicy{
		NetworkPolicy:                    np,
		IngressPolicyClusterWideExposure: k8s.NewPolicyConnections(),
		EgressPolicyClusterWideExposure:  k8s.NewPolicyConnections(),
	}
	if _, ok := pe.netpolsMap[netpolNamespace][np.Name]; ok {
		return errors.New(alerts.NPWithSameNameError(types.NamespacedName{Namespace: netpolNamespace, Name: np.Name}.String()))
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
		// networkpolicy is a namespace-scoped policy (and not cluster-scoped)
		err = pe.generateRepresentativePeers(rulesSelectors, np.Namespace, false)
	}
	// clear the cache on netpols changes
	pe.cache.clear()
	return err
}

func (pe *PolicyEngine) insertAdminNetworkPolicy(anp *apisv1a.AdminNetworkPolicy) error {
	if pe.adminNetpolsMap[anp.Name] {
		return errors.New(alerts.ANPsWithSameNameErr(anp.Name))
	}
	newAnp := &k8s.AdminNetworkPolicy{
		AdminNetworkPolicy:               anp,
		IngressPolicyClusterWideExposure: k8s.NewPolicyConnections(),
		EgressPolicyClusterWideExposure:  k8s.NewPolicyConnections(),
	}
	pe.adminNetpolsMap[anp.Name] = true
	pe.sortedAdminNetpols = append(pe.sortedAdminNetpols, newAnp)
	var err error
	// for exposure analysis only: scan the anp ingress and egress rules:
	// 1. to store connections from/to entire cluster
	// 2. to get selectors and generate representativePeers
	if pe.exposureAnalysisFlag {
		rulesSelectors, scanErr := newAnp.GetPolicyRulesSelectorsAndUpdateExposureClusterWideConns()
		if scanErr != nil {
			return scanErr
		}
		// adminNetworkPolicy is a cluster-scoped policy
		err = pe.generateRepresentativePeers(rulesSelectors, "", true)
	}
	return err
}

func (pe *PolicyEngine) insertBaselineAdminNetworkPolicy(banp *apisv1a.BaselineAdminNetworkPolicy) error {
	if pe.baselineAdminNetpol != nil { // @todo : should this be a warning? the last banp the one considered
		return errors.New(alerts.BANPAlreadyExists)
	}
	if banp.Name != "default" { // "You must use default as the name when creating a BaselineAdminNetworkPolicy object."
		// see https://www.redhat.com/en/blog/using-adminnetworkpolicy-api-to-secure-openshift-cluster-networking
		// or this: https://pkg.go.dev/sigs.k8s.io/network-policy-api@v0.1.5/apis/v1alpha1#BaselineAdminNetworkPolicy
		return errors.New(alerts.BANPNameAssertion)
	}
	newBanp := &k8s.BaselineAdminNetworkPolicy{
		BaselineAdminNetworkPolicy:       banp,
		IngressPolicyClusterWideExposure: k8s.NewPolicyConnections(),
		EgressPolicyClusterWideExposure:  k8s.NewPolicyConnections(),
	}
	pe.baselineAdminNetpol = newBanp
	var err error
	// for exposure analysis only: scan the banp ingress and egress rules:
	// 1. to store connections from/to entire cluster
	// 2. to get selectors and generate representativePeers
	if pe.exposureAnalysisFlag {
		rulesSelectors, scanErr := newBanp.GetPolicyRulesSelectorsAndUpdateExposureClusterWideConns()
		if scanErr != nil {
			return scanErr
		}
		// baselineAdminNetworkPolicy is a cluster-scoped policy
		err = pe.generateRepresentativePeers(rulesSelectors, "", true)
	}
	return err
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
// Deprecated - instead using funcs GetWorkloadPeersList and GetIPBlockPeersLists
func (pe *PolicyEngine) GetPeersList() ([]Peer, error) {
	_, _, res, err := pe.GetIPBlockPeersLists()
	if err != nil {
		return nil, err
	}
	workloads, err := pe.GetWorkloadPeersList()
	if err != nil {
		return nil, err
	}
	res = append(res, workloads...)
	return res, nil
}

// GetWorkloadPeersList returns a slice of peers from all PolicyEngine resources
// get peers in level of workloads (pod owners) of type WorkloadPeer
func (pe *PolicyEngine) GetWorkloadPeersList() ([]Peer, error) {
	podOwnersMap, err := pe.createPodOwnersMap()
	if err != nil {
		return nil, err
	}
	res := make([]Peer, len(podOwnersMap))
	index := 0
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

// GetIPBlockPeersLists returns slices of src and dst IP-Block peers from all policy resources
// also returns one disjoint union src and dst ip-block peers slice
func (pe *PolicyEngine) GetIPBlockPeersLists() (srcIPPeers, dstIPPeers, disjointIPPeers []Peer, err error) {
	srcIPBlocks, dstIPBlocks, allIPBlocks, err := pe.getDisjointIPBlocks()
	if err != nil {
		return nil, nil, nil, err
	}
	srcIPPeers = make([]Peer, len(srcIPBlocks))
	dstIPPeers = make([]Peer, len(dstIPBlocks))
	for i := range srcIPBlocks {
		srcIPPeers[i] = &k8s.IPBlockPeer{IPBlock: srcIPBlocks[i]}
	}
	for i := range dstIPBlocks {
		dstIPPeers[i] = &k8s.IPBlockPeer{IPBlock: dstIPBlocks[i]}
	}
	for i := range allIPBlocks {
		disjointIPPeers = append(disjointIPPeers, &k8s.IPBlockPeer{IPBlock: allIPBlocks[i]})
	}
	return srcIPPeers, dstIPPeers, disjointIPPeers, nil
}

// getDisjointIPBlocks returns two slices of disjoint ip-blocks from all policy resources;
// one slice from ingress rules - srcIpbList
// and  the other dstIpbList from egress rules
func (pe *PolicyEngine) getDisjointIPBlocks() (srcIpbList, dstIpbList, allIpsList []*netset.IPBlock, err error) {
	srcIPBlocks, dstIPBlocks, err := pe.getDisjointIPBlocksFromNetpols()
	if err != nil {
		return nil, nil, nil, err
	}
	// in (B)Admin netpols only egress rules may contains ip addresses - so only dst-s may contain disjointed ip-blocks peers
	anpDstIpbList, err := pe.getDisjointIPBlocksFromAdminNetpols()
	if err != nil {
		return nil, nil, nil, err
	}
	dstIPBlocks = append(dstIPBlocks, anpDstIpbList...)
	if pe.baselineAdminNetpol != nil {
		banpDstIPList, err := pe.baselineAdminNetpol.GetReferencedIPBlocks()
		if err != nil {
			return nil, nil, nil, err
		}
		dstIPBlocks = append(dstIPBlocks, banpDstIPList...)
	}
	newAll := netset.GetCidrAll()
	disjointSrcRes := netset.DisjointIPBlocks(srcIPBlocks, []*netset.IPBlock{newAll})
	disjointDstRes := netset.DisjointIPBlocks(dstIPBlocks, []*netset.IPBlock{newAll})
	disjointAllIps := netset.DisjointIPBlocks(disjointSrcRes, disjointDstRes)
	return disjointSrcRes, disjointDstRes, disjointAllIps, nil
}

// getDisjointIPBlocksFromNetpols returns src and dst slices of disjoint ip-blocks from all netpols
// (NetworkPolicy objects)
func (pe *PolicyEngine) getDisjointIPBlocksFromNetpols() (srcIpbList, dstIpbList []*netset.IPBlock, err error) {
	for _, nsMap := range pe.netpolsMap {
		for _, policy := range nsMap {
			policySrcIps, policyDstIps, err := policy.GetReferencedIPBlocks()
			if err != nil {
				return nil, nil, err
			}
			srcIpbList = append(srcIpbList, policySrcIps...)
			dstIpbList = append(dstIpbList, policyDstIps...)
		}
	}
	return srcIpbList, dstIpbList, nil
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
		return errors.New(alerts.NilRepresentativePodSelectorsErr)
	}
	nsLabelSelector := objSelectors.NsSelector
	if nsLabelSelector == nil {
		if podNs != "" {
			// if the objSelectors.NsSelector is nil but the podNs is not empty, means inferred from
			// a k8s NetworkPolicy rule with nil nsSelector, which means the namespace of the pod is the namespace of the policy,
			// so adding it as its RepresentativeNsLabelSelector requirement.
			// by this, we ensure a representative peer may only represent the rule it was inferred from
			// and uniqueness of representative peers.
			// (another nework-policy in another namespace, may have a rule with same podSelector, but the namespace will be different-
			// so a different representative peer will be generated)
			nsLabelSelector = &metav1.LabelSelector{MatchLabels: defaultNamespaceLabelsMap(podNs)}
		} else {
			// if the objSelectors.NsSelector is nil and the podNs is empty, means inferred from an
			// (baseline)AdminNetworkPolicy rule with nil namespaceSelector, which means that all namespaces match the rule;
			// so as the RepresentativeNsLabelSelector will assign an empty namespaceSelector (matches all namespaces)
			// * keeping this else although currently it is unreached - since `v1alpha1 Pods *NamespacedPod` field uses
			// `metav1.LabelSelector` (and not pointers); which means it can not be nil, either empty or not.(i.e. already empty)
			// so anyway generating a representative peer with empty namespaceSelector (all namespaces ) for
			// cluster-scoped policy rule without namespaceSelector
			nsLabelSelector = &metav1.LabelSelector{} // all namespaces
		}
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

// LogPoliciesWarnings prints to the logger all warnings raised by policy rules while computing
// allowed connections between peers.
// calling this func once after all computations are done, ensures that :
// - all relevant warnings from looping policy rules are raised
// - each single warning is printed only once to the logger
// - all warns are returned also as []string
func (pe *PolicyEngine) LogPoliciesWarnings() (warns []string) {
	// log warnings from k8s NetworkPolicy objects
	for _, nsMap := range pe.netpolsMap {
		for _, policy := range nsMap {
			warns = append(warns, policy.LogWarnings(pe.logger)...)
		}
	}
	// log warnings from AdminNetworkPolicy objects
	for _, anp := range pe.sortedAdminNetpols {
		warns = append(warns, anp.LogWarnings(pe.logger)...)
	}
	// log warnings from the BaselineAdminNetworkPolicy
	if pe.baselineAdminNetpol != nil {
		warns = append(warns, pe.baselineAdminNetpol.LogWarnings(pe.logger)...)
	}
	return warns
}
