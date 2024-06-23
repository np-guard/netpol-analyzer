/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package eval

import (
	"errors"
	"fmt"

	"k8s.io/apimachinery/pkg/labels"

	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval/internal/k8s"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// this file contains eval.PolicyEngine funcs which are related to exposure-analysis feature

// any fake namespace added will start with following prefix for ns name and following pod name
const repNsNamePrefix = "representative-namespace-"

func generateNewNamespaceName(policyName string, index int) string {
	return repNsNamePrefix + policyName + fmt.Sprint(index)
}

func generateNewPodName(index int) string {
	return k8s.RepresentativePodName + "-" + fmt.Sprint(index)
}

// generateRepresentativePeers : generates and adds to policy engine representative peers where each peer
// has namespace and pod labels inferred from single entry of selectors in a policy rule list;
//
// - for example, if a rule within policy has an entry: namespaceSelector "foo: managed", then a representative pod in such a
// namespace with those labels will be added, representing all potential pods in such a namespace.
// - generated representative peers are unique; i.e. if different rules (e.g in different policies or different directions)
// has same labels, one representative peer is generated to represent both
func (pe *PolicyEngine) generateRepresentativePeers(selectors []k8s.SingleRuleSelectors, policyName, policyNs string) (err error) {
	for i := range selectors {
		// 1. first convert each rule selectors' pair (podSelector and namespaceSelector) to pairs of its matching labels maps.
		// each pair contains map of namespaceLabels and map of podLabels
		// a representative peer will be generated for each pair
		labelsPairs := k8s.ConvertSelectorsToLabelsCombinations(&selectors[i])
		// 2. secondly: for each pair of labels, generate a representative peer
		err := pe.generateRepresentativePeerPerLabelsPair(labelsPairs, selectors[i].PolicyNsFlag, policyName, policyNs, i)
		if err != nil {
			return err
		}
	}
	return nil
}

// generateRepresentativePeerPerLabelsPair : gets list of pairs of namespaceLabels and podLabels maps,
// and creates a new representative peer for each pair.
// if policyNsFlag is true, i.e. the namespaceSelector is nil, a representative peer is created in
// the namespace of the policy with given podLabels maps.
func (pe *PolicyEngine) generateRepresentativePeerPerLabelsPair(labelsPairs k8s.LabelsPairsList, policyNsFlag bool, policyName,
	policyNs string, selectorNum int) (err error) {
	for i := range labelsPairs {
		// if ns labels of the rule selector was nil, then the namespace of the pod is same as the policy's namespace
		if policyNsFlag {
			_, err = pe.AddPodByNameAndNamespace(generateNewPodName(i+selectorNum), policyNs, &labelsPairs[i])
		} else {
			_, err = pe.AddPodByNameAndNamespace(generateNewPodName(i+selectorNum), generateNewNamespaceName(policyName, i+selectorNum),
				&labelsPairs[i])
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// extractLabelsAndRefineRepresentativePeers extracts the labels of the given pod object and its namespace and refine matching peers
// helping func - added in order to avoid code dup. in upsertWorkload and upsertPod
func (pe *PolicyEngine) extractLabelsAndRefineRepresentativePeers(podObj *k8s.Pod) error {
	// since namespaces are already upserted; if pod's ns not existing resolve it
	if _, ok := pe.namspacesMap[podObj.Namespace]; !ok {
		// the "kubernetes.io/metadata.name" is added automatically to the ns; so representative peers with such selector will be refined
		err := pe.resolveSingleMissingNamespace(podObj.Namespace, nil)
		if err != nil {
			return err
		}
	}
	// check if there are representative peers in the policy engine which match the current pod; if yes remove them
	pe.refineRepresentativePeersMatchingLabels(podObj.Labels, pe.namspacesMap[podObj.Namespace].Labels)
	return nil
}

// refineRepresentativePeersMatchingLabels removes from the policy engine all representative peers
// with labels matching the given labels of a real pod
// representative peers matching any-namespace or any-pod in a namespace will not be removed.
func (pe *PolicyEngine) refineRepresentativePeersMatchingLabels(realPodLabels, realNsLabels map[string]string) {
	keysToDelete := make([]string, 0)
	// look for representative peers with labels matching the given real pod's (and its namespace) labels
	for key, peer := range pe.representativePeersMap {
		potentialPodSelector := labels.SelectorFromSet(labels.Set(peer.Pod.Labels))
		potentialNsSelector := labels.SelectorFromSet(labels.Set(peer.PotentialNamespaceLabels))
		if potentialNsSelector.Empty() {
			// empty --representative peer that matches any-namespace, thus will not be removed
			// note that if the policy had nil namespaceSelector, it would be converted to the namespace of the policy
			continue
		}
		if potentialPodSelector.Empty() {
			// empty/nil podSelector means representative peer that matches any-pod in the representative namespace,
			// thus will not be removed
			// note that there is no representative peer with both empty namespace and pod selector; that case was handled
			// in the general conns compute and won't get here.
			continue
		}
		if peer.HasUnusualNsLabels || peer.Pod.HasUnusualPodLabels {
			// a representative peer with labels inferred from requirements of matchExpression with operators : Exists/DoesNotExist/NotIn
			// will not be refined
			continue
		}
		// representative peer with regular labels inferred from selectors with matchLabels or matchExpression with operator In;
		// is removed (refined) if matches both realPodLabels and realNsLabels.
		if potentialPodSelector.Matches(labels.Set(realPodLabels)) && potentialNsSelector.Matches(labels.Set(realNsLabels)) {
			keysToDelete = append(keysToDelete, key)
		}
	}

	// delete redundant representative peers
	for _, k := range keysToDelete {
		delete(pe.representativePeersMap, k)
	}
}

// /////////////////////////////////

// isPeerAWorkloadPeer checks and returns the peer if it is a k8s workload peer
func isPeerAWorkloadPeer(p Peer) (*k8s.WorkloadPeer, error) {
	peer, ok := p.(*k8s.WorkloadPeer)
	if !ok { // should not get here
		return nil, errors.New(netpolerrors.NotPeerErrStr(p.String()))
	}
	return peer, nil
}

// IsPeerProtected returns if the peer is protected by network policies on the given ingress/egress direction
// relevant only for workloadPeer
func (pe *PolicyEngine) IsPeerProtected(p Peer, isIngress bool) (bool, error) {
	peer, err := isPeerAWorkloadPeer(p)
	if err != nil { // should not get here
		return false, err
	}
	if isIngress {
		return peer.Pod.IngressExposureData.IsProtected, nil
	}
	return peer.Pod.EgressExposureData.IsProtected, nil
}

// GetPeerXgressEntireClusterConn returns the connection to entire cluster on given ingress/egress direction
// relevant only for workloadPeer
func (pe *PolicyEngine) GetPeerXgressEntireClusterConn(p Peer, isIngress bool) (*common.ConnectionSet, error) {
	peer, err := isPeerAWorkloadPeer(p)
	if err != nil { // should not get here
		return nil, err
	}
	if isIngress {
		return peer.Pod.IngressExposureData.EntireClusterConnection, nil
	}
	return peer.Pod.EgressExposureData.EntireClusterConnection, nil
}

/////////////////////////////////////////////

// IsRepresentativePeer returns whether the peer is representative peer (inferred from netpol rule)
func (pe *PolicyEngine) IsRepresentativePeer(peer Peer) bool {
	_, ok := peer.(*k8s.RepresentativePeer)
	return ok
}

// GetPeerLabels returns the labels defining the given representative peer and its namespace
// relevant only for RepresentativePeer
func (pe *PolicyEngine) GetPeerLabels(p Peer) (podLabels, nsLabels map[string]string, err error) {
	peer, ok := p.(*k8s.RepresentativePeer)
	if !ok { // should not get here
		return nil, nil, errors.New(netpolerrors.NotRepresentativePeerErrStr(p.String()))
	}
	return peer.Pod.Labels, peer.PotentialNamespaceLabels, nil
}
