/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package eval

import (
	"errors"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval/internal/k8s"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// this file contains eval.PolicyEngine funcs which are related to exposure-analysis feature

// generateRepresentativePeers : generates and adds to policy engine representative peers where each peer
// has namespace labelSelector and pod labelSelector inferred from single entry of selectors in a policy rules list;
//
// - for example, if a rule within policy has an entry: namespaceSelector "foo: managed", then a representative pod
// with this labelSelector will be added, representing all potential pods in such a namespace.
// - generated representative peers are unique; i.e. if different rules (e.g in different policies or different directions)
// has same selectors, one representative peer is generated to represent both.
// - note that :
// - if the rule's namespaceSelector is nil, then the representative pod is created in the policy's Namespace (as it is a real namespace)
// - if the rule's namespaceSelector is not nil, no representative namespace will be generated (representative pod has empty namespace name)
// anyway, the representative pod will store the namespace data.
func (pe *PolicyEngine) generateRepresentativePeers(selectors []k8s.SingleRuleSelectors, policyNs string) (err error) {
	for i := range selectors {
		podNs := "" // by default: representative peer has no namespace; (don't generate representative namespaces)
		if selectors[i].NsSelector == nil {
			// if namespaceSelector of the rule was nil, then the namespace of the pod is same as the policy's namespace
			// i.e. the namespace name of the policy should be assigned to the representative pod's Namespace (string field)
			podNs = policyNs
		}
		err = pe.addRepresentativePod(podNs, &selectors[i])
		if err != nil {
			return err
		}
	}
	return nil
}

// removeRedundantRepresentativePeers extracts the labels of the given pod object and its namespace and refine matching
// representative-peers, i.e. delete a representative pod if the given real pod matches its selectors
// (applied for representative-peers with matchLabels only, no matchExpression).
// helping func - added in order to avoid code dup. in upsertWorkload and upsertPod
func (pe *PolicyEngine) removeRedundantRepresentativePeers(podObj *k8s.Pod) error {
	// since namespaces are already upserted; if pod's ns not existing resolve it
	if _, ok := pe.namspacesMap[podObj.Namespace]; !ok {
		// the "kubernetes.io/metadata.name" is added automatically to the ns; so representative peers with such selector will be refined
		err := pe.resolveSingleMissingNamespace(podObj.Namespace)
		if err != nil {
			return err
		}
	}
	// check if there are representative peers in the policy engine which match the current pod; if yes remove them
	pe.removeRepresentativePeersMatchingLabels(podObj.Labels, pe.namspacesMap[podObj.Namespace].Labels)
	return nil
}

// removeRepresentativePeersMatchingLabels removes from the policy engine all representative peers
// with labels matching the given labels of a real pod
// representative peers matching any-namespace or any-pod in a namespace will not be removed.
// representative peers inferred from rules containing matchExpressions will not be removed either
func (pe *PolicyEngine) removeRepresentativePeersMatchingLabels(realPodLabels, realNsLabels map[string]string) {
	keysToDelete := make([]string, 0)
	// look for representative peers with labels matching the given real pod's (and its namespace) labels
	for key, repPeer := range pe.representativePeersMap {
		if repPeer.Pod.RepresentativePodLabelSelector == nil {
			continue // nil podSelector means any-pod
		}
		// note that if the policy had nil namespaceSelector, then representative pod's RepresentativeNsLabelSelector would
		// contain the namespace of the policy requirement
		// note that there is no representative peer with both empty namespace and pod selector; that case was handled
		// and assigned to the policy's cluster wide exposure and won't get here.
		if len(repPeer.Pod.RepresentativePodLabelSelector.MatchExpressions) > 0 ||
			len(repPeer.Pod.RepresentativeNsLabelSelector.MatchExpressions) > 0 {
			// a representative peer with requirements inferred from selectors with matchExpression will not be refined
			continue
		}

		// matchExpressions of representative peer are empty , check labels
		potentialPodSelector := labels.SelectorFromSet(labels.Set(repPeer.Pod.RepresentativePodLabelSelector.MatchLabels))
		potentialNsSelector := labels.SelectorFromSet(labels.Set(repPeer.Pod.RepresentativeNsLabelSelector.MatchLabels))
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
		// representative peer with regular labels inferred from selectors with matchLabels only;
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
		return peer.Pod.IngressExposureData.ClusterWideConnection, nil
	}
	return peer.Pod.EgressExposureData.ClusterWideConnection, nil
}

/////////////////////////////////////////////

// IsRepresentativePeer returns whether the peer is representative peer (inferred from netpol rule)
func (pe *PolicyEngine) IsRepresentativePeer(peer Peer) bool {
	_, ok := peer.(*k8s.RepresentativePeer)
	return ok
}

// GetPeerLabels returns the labels defining the given representative peer and its namespace
// relevant only for RepresentativePeer
func (pe *PolicyEngine) GetPeerLabels(p Peer) (podLabels, nsLabels v1.LabelSelector, err error) {
	peer, ok := p.(*k8s.RepresentativePeer)
	if !ok { // should not get here
		return v1.LabelSelector{}, v1.LabelSelector{}, errors.New(netpolerrors.NotRepresentativePeerErrStr(p.String()))
	}
	podLabels = v1.LabelSelector{}
	if peer.Pod.RepresentativePodLabelSelector != nil {
		podLabels = *peer.Pod.RepresentativePodLabelSelector.DeepCopy()
	}
	nsLabels = v1.LabelSelector{}
	if peer.Pod.RepresentativeNsLabelSelector != nil {
		nsLabels = *peer.Pod.RepresentativeNsLabelSelector.DeepCopy()
	}
	return podLabels, nsLabels, nil
}
