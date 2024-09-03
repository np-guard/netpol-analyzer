/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package k8s

import (
	"errors"
	"fmt"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	apisv1a "sigs.k8s.io/network-policy-api/apis/v1alpha1"

	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

//// first section in the file contains:
// funcs which are commonly used by AdminNetworkPolicy and BaselineAdminNetworkPolicy types

// note that : according to "sigs.k8s.io/network-policy-api/apis/v1alpha1", AdminNetworkPolicy and BaselineAdminNetworkPolicy
// both use same objects type for :
// field: Subject, type: AdminNetworkPolicySubject
// field: From, type: []AdminNetworkPolicyIngressPeer
// field: To, type: []AdminNetworkPolicyEgressPeer
// field: Ports, type: *[]AdminNetworkPolicyPort
//
// But use different types for following fields:
// Spec, Ingress, Egress, Action, Status - then funcs using/looping any of these fields are not common (sub funcs are common)

const ruleErrTitle = "Error in rule"

// doesNamespacesFieldMatchPeer returns true if the given namespaces LabelSelector matches the given peer
func doesNamespacesFieldMatchPeer(namespaces *metav1.LabelSelector, peer Peer) (bool, error) {
	if peer.PeerType() == IPBlockType {
		return false, nil // namespaces does not select IPs
	}
	namespacesSelector, err := metav1.LabelSelectorAsSelector(namespaces)
	if err != nil {
		return false, err
	}
	return namespacesSelector.Matches(labels.Set(peer.GetPeerNamespace().Labels)), nil
}

// doesPodsFieldMatchPeer returns if the given NamespacedPod object matches the given peer
// a NamespacedPod object contains both NamespaceSelector and PodSelector
func doesPodsFieldMatchPeer(pods *apisv1a.NamespacedPod, peer Peer) (bool, error) {
	if peer.PeerType() == IPBlockType {
		return false, nil // pods does not select IPs
	}
	nsSelector, err := metav1.LabelSelectorAsSelector(&pods.NamespaceSelector)
	if err != nil {
		return false, err
	}
	podSelector, err := metav1.LabelSelectorAsSelector(&pods.PodSelector)
	if err != nil {
		return false, err
	}
	return nsSelector.Matches(labels.Set(peer.GetPeerNamespace().Labels)) && podSelector.Matches(labels.Set(peer.GetPeerPod().Labels)), nil
}

// egressRuleSelectsPeer checks if the given AdminNetworkPolicyEgressPeer rule selects the given peer
// currently supposing an egressPeer rule may contain only Namespaces/ Pods Fields,
// @todo support also egress rule peer with Networks field
// @todo if egress rule peer contains Nodes field, raise a warning that we don't support it
//
//nolint:dupl // this loops egress spec - input is []apisv1a.AdminNetworkPolicyEgressPeer // todo : use generics
func egressRuleSelectsPeer(rulePeers []apisv1a.AdminNetworkPolicyEgressPeer, dst Peer) (bool, error) {
	for i := range rulePeers {
		// only one field in a `apisv1a.AdminNetworkPolicyEgressPeer` may be not nil (set)
		if (rulePeers[i].Namespaces == nil) == (rulePeers[i].Pods == nil) {
			return false, errors.New(netpolerrors.OneFieldSetRulePeerErr)
		}
		fieldMatch := false
		var err error
		if rulePeers[i].Namespaces != nil {
			fieldMatch, err = doesNamespacesFieldMatchPeer(rulePeers[i].Namespaces, dst)
		} else { // else Pods is not nil
			fieldMatch, err = doesPodsFieldMatchPeer(rulePeers[i].Pods, dst)
		}
		if err != nil {
			return false, err
		}
		if fieldMatch {
			return true, nil
		}
	}
	return false, nil
}

// ingressRuleSelectsPeer checks if the given AdminNetworkPolicyIngressPeer rule selects the given peer
//
//nolint:dupl // this loops ingress spec - input is []apisv1a.AdminNetworkPolicyIngressPeer // todo: use generics
func ingressRuleSelectsPeer(rulePeers []apisv1a.AdminNetworkPolicyIngressPeer, src Peer) (bool, error) {
	for i := range rulePeers {
		// only one field in a `apisv1a.AdminNetworkPolicyIngressPeer` may be not nil (set)
		if (rulePeers[i].Namespaces == nil) == (rulePeers[i].Pods == nil) {
			return false, errors.New(netpolerrors.OneFieldSetRulePeerErr)
		}
		fieldMatch := false
		var err error
		if rulePeers[i].Namespaces != nil {
			fieldMatch, err = doesNamespacesFieldMatchPeer(rulePeers[i].Namespaces, src)
		} else { // else Pods is not nil
			fieldMatch, err = doesPodsFieldMatchPeer(rulePeers[i].Pods, src)
		}
		if err != nil {
			return false, err
		}
		if fieldMatch {
			return true, nil
		}
	}
	return false, nil
}

// ruleConnections returns the connectionSet from the current rule.Ports
func ruleConnections(ports *[]apisv1a.AdminNetworkPolicyPort, dst Peer) (*common.ConnectionSet, error) {
	if ports == nil {
		return common.MakeConnectionSet(true), nil // If Ports is not set then the rule does not filter traffic via port.
	}
	res := common.MakeConnectionSet(false)
	for _, anpPort := range *ports {
		if !onlyOnePortFieldsSet(anpPort) {
			return nil, errors.New(netpolerrors.ANPPortsError)
		}
		protocol := v1.ProtocolTCP
		portSet := common.MakePortSet(false)
		switch {
		case anpPort.PortNumber != nil:
			if anpPort.PortNumber.Protocol != "" {
				protocol = anpPort.PortNumber.Protocol
			}
			portSet.AddPort(intstr.FromInt32(anpPort.PortNumber.Port))
		case anpPort.NamedPort != nil:
			podProtocol, podPort := dst.GetPeerPod().ConvertPodNamedPort(*anpPort.NamedPort)
			if podPort == common.NoPort { // pod does not have this named port in its container
				continue // @todo should raise a warning
			}
			if podProtocol != "" {
				protocol = podProtocol
			}
			portSet.AddPort(intstr.FromInt32(podPort))
		case anpPort.PortRange != nil:
			if anpPort.PortRange.Protocol != "" {
				protocol = anpPort.PortRange.Protocol
			}
			if isEmptyPortRange(anpPort.PortRange.Start, anpPort.PortRange.End) {
				continue // @todo should raise a warning
			}
			portSet.AddPortRange(int64(anpPort.PortRange.Start), int64(anpPort.PortRange.End))
		}
		res.AddConnection(protocol, portSet)
	}
	return res, nil
}

// checks if the AdminNetworkPolicyPort contains exactly one field (Exactly one field must be set)
func onlyOnePortFieldsSet(anpPort apisv1a.AdminNetworkPolicyPort) bool {
	count := 0
	if anpPort.PortNumber != nil {
		count++
	}
	if anpPort.PortRange != nil {
		count++
	}
	if anpPort.NamedPort != nil {
		count++
	}
	return count == 1
}

// subjectSelectsPeer returns if the given subject of the (baseline)adminNetworkPolicy selects the given peer
func subjectSelectsPeer(anpSubject apisv1a.AdminNetworkPolicySubject, p Peer) (bool, error) {
	if (anpSubject.Namespaces == nil) == (anpSubject.Pods == nil) {
		// (Baseline)AdminNetworkPolicySubject should contain exactly one field
		// (https://github.com/kubernetes-sigs/network-policy-api/blob/v0.1.5/apis/v1alpha1/shared_types.go#L27))
		return false, errors.New(netpolerrors.OneFieldSetSubjectErr)
	}
	if anpSubject.Namespaces != nil {
		return doesNamespacesFieldMatchPeer(anpSubject.Namespaces, p)
	}
	// else: Subject.Pods is not empty (Subject.Pods contains both NamespaceSelector and PodSelector)
	return doesPodsFieldMatchPeer(anpSubject.Pods, p)
}

////////////////////////////////////////////////////////////////////////////////////////////

// AdminNetworkPolicy is an alias for k8s adminNetworkPolicy object
type AdminNetworkPolicy apisv1a.AdminNetworkPolicy

// @todo: TBD if using generics may help avoid duplicates in the files adminnetpol.go and baseline_admin_netpol.go

// Selects returns true if the admin network policy's Spec.Subject selects the peer and if the required direction is in the policy spec
func (anp *AdminNetworkPolicy) Selects(p Peer, isIngress bool) (bool, error) {
	if p.PeerType() == IPBlockType {
		// adminNetworkPolicy is a cluster level resource which selects peers with their namespaceSelectors and podSelectors only,
		// so it might not select IPs
		return false, nil
	}
	if !anp.adminPolicyAffectsDirection(isIngress) {
		return false, nil
	}
	// check if the subject selects the given peer
	return subjectSelectsPeer(anp.Spec.Subject, p)
}

// adminPolicyAffectsDirection returns whether the anp affects the given direction or not.
// anp affects a direction, if its spec has rules on that direction
func (anp *AdminNetworkPolicy) adminPolicyAffectsDirection(isIngress bool) bool {
	if isIngress {
		// ANPs with no ingress rules do not affect ingress traffic.
		return len(anp.Spec.Ingress) > 0
	}
	// ANPs with no egress rules do not affect egress traffic.
	return len(anp.Spec.Egress) > 0
}

// anpErr returns string format of an error in a rule in admin netpol
func (anp *AdminNetworkPolicy) anpRuleErr(ruleName, description string) error {
	return fmt.Errorf("admin network policy %q: %s %q: %s", anp.Name, ruleErrTitle, ruleName, description)
}

// GetIngressPolicyConns returns the connections from the ingress rules selecting the src in spec of the adminNetworkPolicy
//
//nolint:dupl // this loops Ingress spec - different types
func (anp *AdminNetworkPolicy) GetIngressPolicyConns(src, dst Peer) (*PolicyConnections, error) {
	res := InitEmptyPolicyConnections()
	for _, rule := range anp.Spec.Ingress {
		rulePeers := rule.From
		if len(rulePeers) == 0 {
			return nil, anp.anpRuleErr(rule.Name, netpolerrors.ANPIngressRulePeersErr)
		}
		rulePorts := rule.Ports
		peerSelected, err := ingressRuleSelectsPeer(rulePeers, src)
		if err != nil {
			return nil, anp.anpRuleErr(rule.Name, err.Error())
		}
		if !peerSelected {
			continue
		}

		ruleConns, err := ruleConnections(rulePorts, dst)
		if err != nil {
			return nil, anp.anpRuleErr(rule.Name, err.Error())
		}
		err = res.UpdateWithRuleConns(ruleConns, string(rule.Action))
		if err != nil {
			return nil, anp.anpRuleErr(rule.Name, err.Error())
		}
	}
	return res, nil
}

// GetEgressPolicyConns returns the connections from the egress rules selecting the dst in spec of the adminNetworkPolicy
//
//nolint:dupl // this loops Egress spec - different types
func (anp *AdminNetworkPolicy) GetEgressPolicyConns(dst Peer) (*PolicyConnections, error) {
	res := InitEmptyPolicyConnections()
	for _, rule := range anp.Spec.Egress {
		rulePeers := rule.To
		if len(rulePeers) == 0 {
			return nil, anp.anpRuleErr(rule.Name, netpolerrors.ANPEgressRulePeersErr)
		}
		rulePorts := rule.Ports
		peerSelected, err := egressRuleSelectsPeer(rulePeers, dst)
		if err != nil {
			return nil, anp.anpRuleErr(rule.Name, err.Error())
		}
		if !peerSelected {
			continue
		}

		ruleConns, err := ruleConnections(rulePorts, dst)
		if err != nil {
			return nil, anp.anpRuleErr(rule.Name, err.Error())
		}
		err = res.UpdateWithRuleConns(ruleConns, string(rule.Action))
		if err != nil {
			return nil, anp.anpRuleErr(rule.Name, err.Error())
		}
	}
	return res, nil
}

const (
	minPriority = 0
	maxPriority = 1000
)

// HasValidPriority returns if the priority in a valid range
func (anp *AdminNetworkPolicy) HasValidPriority() bool {
	// note: k8s defines "1000" as the maximum numeric value for priority
	// but openshift currently only support priority values between 0 and 99
	// current implementation satisfies k8s requirement
	if anp.Spec.Priority >= minPriority && anp.Spec.Priority <= maxPriority {
		return true
	}
	return false
}
