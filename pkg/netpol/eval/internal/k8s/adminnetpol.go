/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package k8s

import (
	"errors"
	"fmt"
	"net"
	"strconv"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	apisv1a "sigs.k8s.io/network-policy-api/apis/v1alpha1"

	"github.com/np-guard/models/pkg/netset"

	"github.com/np-guard/netpol-analyzer/pkg/logger"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/alerts"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// AdminNetworkPolicy is an alias for k8s adminNetworkPolicy object
type AdminNetworkPolicy struct {
	*apisv1a.AdminNetworkPolicy                 // embedding k8s admin-network-policy object
	warnings                    common.Warnings // set of warnings which are raised by the anp
	// following data stored in preprocessing when exposure-analysis is on;
	// IngressPolicyClusterWideExposure contains:
	// - the maximal connection-sets which the admin-policy's rules allow/deny/pass from all namespaces in the cluster on ingress direction
	// those conns are inferred rules with empty selectors
	IngressPolicyClusterWideExposure *PolicyConnections
	// EgressPolicyClusterWideExposure contains:
	// - the maximal connection-sets which the admin-policy's rules allow/deny/pass to all namespaces in the cluster on egress direction
	// those conns are inferred rules with empty selectors
	EgressPolicyClusterWideExposure *PolicyConnections
}

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
	errTitle := fmt.Sprintf("%s %q: ", anpErrTitle, anp.Name)
	return subjectSelectsPeer(anp.Spec.Subject, p, errTitle)
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

const (
	anpErrTitle      = "admin network policy"
	anpErrWarnFormat = anpErrTitle + " %q: in rule %q: %s"
)

// anpErr returns string format of an error in a rule in admin netpol
func (anp *AdminNetworkPolicy) anpRuleErr(ruleName, description string) error {
	return fmt.Errorf(anpErrWarnFormat, anp.Name, ruleName, description)
}

// anpRuleWarning returns string format of a warning message for an admin network policy rule.
func (anp *AdminNetworkPolicy) anpRuleWarning(ruleName, warning string) string {
	return fmt.Sprintf(anpErrWarnFormat, anp.Name, ruleName, warning)
}

// savePolicyWarnings saves any warnings generated for an admin network policy rule in the policy's warnings set.
func (anp *AdminNetworkPolicy) savePolicyWarnings(ruleName string) {
	if anp.warnings == nil {
		anp.warnings = make(map[string]bool)
	}
	for _, warning := range ruleWarnings {
		anp.warnings.AddWarning(anp.anpRuleWarning(ruleName, warning))
	}
}

// GetIngressPolicyConns returns the connections from the ingress rules selecting the src in spec of the adminNetworkPolicy
func (anp *AdminNetworkPolicy) GetIngressPolicyConns(src, dst Peer) (*PolicyConnections, error) {
	res := NewPolicyConnections()
	for _, rule := range anp.Spec.Ingress { // rule is apisv1a.AdminNetworkPolicyIngressRule
		rulePeers := rule.From
		rulePorts := rule.Ports
		ruleWarnings = []string{} // clear the ruleWarnings (for each rule)
		// following func also updates the warnings var
		err := updateConnsIfIngressRuleSelectsPeer(rulePeers, rulePorts,
			ruleExplanationStr(anp.fullName(), rule.Name, string(rule.Action), true),
			src, dst, res, string(rule.Action), false)
		anp.savePolicyWarnings(rule.Name)
		if err != nil {
			return nil, anp.anpRuleErr(rule.Name, err.Error())
		}
	}
	return res, nil
}

// GetEgressPolicyConns returns the connections from the egress rules selecting the dst in spec of the adminNetworkPolicy
func (anp *AdminNetworkPolicy) GetEgressPolicyConns(dst Peer) (*PolicyConnections, error) {
	res := NewPolicyConnections()
	for _, rule := range anp.Spec.Egress { // rule is apisv1a.AdminNetworkPolicyEgressRule
		rulePeers := rule.To
		rulePorts := rule.Ports
		ruleWarnings = []string{} // clear ruleWarnings (for each rule), so it is updated by following call
		err := updateConnsIfEgressRuleSelectsPeer(rulePeers, rulePorts,
			ruleExplanationStr(anp.fullName(), rule.Name, string(rule.Action), false),
			dst, res, string(rule.Action), false)
		anp.savePolicyWarnings(rule.Name)
		if err != nil {
			return nil, anp.anpRuleErr(rule.Name, err.Error())
		}
	}
	return res, nil
}

// HasValidPriority returns if the priority in a valid range
func (anp *AdminNetworkPolicy) HasValidPriority() bool {
	// note: k8s defines "1000" as the maximum numeric value for priority
	// but openshift currently only support priority values between 0 and 99
	// current implementation satisfies k8s requirement
	return anp.Spec.Priority >= common.MinANPPriority && anp.Spec.Priority <= common.MaxANPPriority
}

// CheckEgressConnAllowed checks if the input conn is allowed/passed/denied or not captured on egress by current admin-network-policy
func (anp *AdminNetworkPolicy) CheckEgressConnAllowed(dst Peer, protocol, port string) (res ANPRulesResult, err error) {
	for _, rule := range anp.Spec.Egress {
		rulePeers := rule.To
		rulePorts := rule.Ports
		ruleWarnings = []string{} // clear ruleWarnings (for each rule), so it is updated by following call
		ruleRes, err := checkIfEgressRuleContainsConn(rulePeers, rulePorts, dst, string(rule.Action), protocol, port, false)
		anp.savePolicyWarnings(rule.Name)
		if err != nil {
			return NotCaptured, anp.anpRuleErr(rule.Name, err.Error())
		}
		if ruleRes == NotCaptured { // next rule
			continue
		}
		return ruleRes, nil
	}
	// getting here means the protocol+port was not captured
	return NotCaptured, nil
}

// CheckIngressConnAllowed checks if the input conn is allowed/passed/denied or not captured on ingress by current admin-network-policy
func (anp *AdminNetworkPolicy) CheckIngressConnAllowed(src, dst Peer, protocol, port string) (res ANPRulesResult, err error) {
	for _, rule := range anp.Spec.Ingress {
		rulePeers := rule.From
		rulePorts := rule.Ports
		ruleWarnings = []string{} // clear ruleWarnings (for each rule), so it is updated by following call
		ruleRes, err := checkIfIngressRuleContainsConn(rulePeers, rulePorts, src, dst, string(rule.Action), protocol, port, false)
		anp.savePolicyWarnings(rule.Name)
		if err != nil {
			return NotCaptured, anp.anpRuleErr(rule.Name, err.Error())
		}
		if ruleRes == NotCaptured { // next rule
			continue
		}
		return ruleRes, nil
	}
	// getting here means the protocol+port was not captured
	return NotCaptured, nil
}

// GetReferencedIPBlocks returns a list of IPBlocks referenced by the AdminNetworkPolicy's Egress rules.
func (anp *AdminNetworkPolicy) GetReferencedIPBlocks() ([]*netset.IPBlock, error) {
	res := []*netset.IPBlock{}
	// in ANP only egress rules may contains ip addresses
	for _, rule := range anp.Spec.Egress {
		ruleRes, err := rulePeersReferencedIPBlocks(rule.To)
		if err != nil {
			return nil, err
		}
		res = append(res, ruleRes...)
	}
	return res, nil
}

func (anp *AdminNetworkPolicy) LogWarnings(l logger.Logger) []string {
	return anp.warnings.LogPolicyWarnings(l)
}

///////////////////////////////////////////////////////////////////////////////////////////////
//// second section in the file contains:
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

// warnings : to contain the warnings from a single rule of an adminNetworkPolicy or a BaselineAdminNetworkPolicy.
// global to be used in the common func, initialized (cleared) and logged by the relevant (B)ANP calling funcs
var ruleWarnings = []string{}

// doesNamespaceSelectorMatchesPeer returns true if the given namespaces LabelSelector matches the given peer's namespace object
func doesNamespaceSelectorMatchesPeer(namespaces *metav1.LabelSelector, peer Peer) (bool, error) {
	if peer.PeerType() == IPBlockType {
		return false, nil // IPs are not namespace-scoped
	}
	peerNamespace := peer.GetPeerNamespace()
	var peerNsLabels map[string]string
	if peerNamespace != nil { // peerNamespace may be nil for representative peers
		peerNsLabels = peerNamespace.Labels
	}
	return selectorsMatch(namespaces, peer.GetPeerPod().RepresentativeNsLabelSelector, peerNsLabels, isPeerRepresentative(peer))
}

// selectorsMatch checks if the given selectors match each other.
// called either with namespace-selectors, or with pod-selectors
// when exposure analysis is on : checks the match between rule selector and the relevant representativePeer selector
// otherwise, checks match between rule-selector and pod/namespace labels
func selectorsMatch(ruleSelector, peerSelector *metav1.LabelSelector, peerLabels map[string]string,
	isPeerRepresentative bool) (selectorsMatch bool, err error) {
	// for exposure analysis (representative-peer), use relevant func to check if representative peer is matched by rule's selector
	if isPeerRepresentative {
		// representative peer is inferred from a rule:
		// - by having representative selector pointing to same reference of the rule's selector
		// - or by having representative labelSelector with requirements equal to the rule's requirements
		// note that if the given ruleSelector is nil, we don't get here.
		return SelectorsFullMatch(ruleSelector, peerSelector)
	} // else for real peer just check if the selector matches the peer's labels
	selector, err := metav1.LabelSelectorAsSelector(ruleSelector)
	if err != nil {
		return false, fmt.Errorf("%s", alerts.SelectorErrTitle+" : "+err.Error())
	}
	return selector.Matches(labels.Set(peerLabels)), nil
}

// doesPodsFieldMatchPeer returns if the given NamespacedPod object matches the given peer
// a NamespacedPod object contains both NamespaceSelector and PodSelector
func doesPodsFieldMatchPeer(pods *apisv1a.NamespacedPod, peer Peer) (bool, error) {
	if peer.PeerType() == IPBlockType {
		return false, nil // *apisv1a.NamespacedPod does not select IPs
	}
	nsMatch, err := doesNamespaceSelectorMatchesPeer(&pods.NamespaceSelector, peer)
	if err != nil {
		return false, err
	}
	if !nsMatch {
		return false, nil
	}
	// namespace selector matches the peer's namespace; return if the podSelector also matches the peer's pod
	return selectorsMatch(&pods.PodSelector, peer.GetPeerPod().RepresentativePodLabelSelector,
		peer.GetPeerPod().Labels, isPeerRepresentative(peer))
}

// doesNetworksFieldMatchPeer checks if the given peer matches the networks field.
// returns true if the peer's IPBlock is contained within any of the cidr-s in networks field
func doesNetworksFieldMatchPeer(networks []apisv1a.CIDR, peer Peer) (bool, error) {
	if peer.GetPeerIPBlock() == nil {
		return false, nil // networks field selects peers via CIDR blocks (IPs).
		// nothing to do with Peer type which is not IPBlock
	}
	for _, cidr := range networks {
		// note that: if the cidr is invalid (will not get here), an error would be raised earlier by GetReferencedIPBlocks
		isIPv6, err := isIPv6Cidr(cidr)
		if err != nil { // invalid cidr
			return false, err
		}
		if isIPv6 { // not supported addresses
			ruleWarnings = append(ruleWarnings, alerts.WarnUnsupportedIPv6Address)
			continue // next cidr
		}
		ipb, err := netset.IPBlockFromCidr(string(cidr))
		if err != nil {
			return false, errors.New(alerts.InvalidCIDRAddr)
		}
		if peer.GetPeerIPBlock().IsSubset(ipb) {
			return true, nil
		}
	}
	return false, nil
}

// egressRuleSelectsPeer checks if the given []AdminNetworkPolicyEgressPeer rule selects the given peer
// AdminNetworkPolicyEgressPeer may define an:
// 1. in-cluster peer by one of  Namespaces/ Pods/ Nodes field
// 2. an external peer with Networks field;
// However, exactly one of the selector pointers must be set for a given peer.
func egressRuleSelectsPeer(rulePeers []apisv1a.AdminNetworkPolicyEgressPeer, dst Peer) (bool, error) {
	for i := range rulePeers {
		// Validate: Exactly one of the `AdminNetworkPolicyEgressPeer`'s selector pointers must be
		// set for a given peer.
		if !validateEgressRuleFields(rulePeers[i]) {
			return false, errors.New(alerts.OneFieldSetRulePeerErr)
		}
		if rulePeers[i].Nodes != nil { // not supported field
			ruleWarnings = append(ruleWarnings, alerts.WarnUnsupportedNodesField)
			continue // next peer
		}
		fieldMatch, err := ruleFieldsSelectsPeer(rulePeers[i].Namespaces, rulePeers[i].Pods, rulePeers[i].Networks, dst)
		if err != nil {
			return false, err
		}
		if fieldMatch {
			return true, nil
		}
	}
	return false, nil
}

// validateEgressRuleFields checks if exactly one field of AdminNetworkPolicyEgressPeer is set.
func validateEgressRuleFields(rulePeers apisv1a.AdminNetworkPolicyEgressPeer) bool {
	count := 0
	if rulePeers.Namespaces != nil {
		count++
	}
	if rulePeers.Pods != nil {
		count++
	}
	if rulePeers.Nodes != nil {
		count++
	}
	if rulePeers.Networks != nil {
		count++
	}
	return count == 1
}

// ruleFieldsSelectsPeer returns wether the input rule field(s) selects the peer.
// note that the validation of the rulePeer already checked in the calling funcs, so exactly one of:
// namespaces , pods , networks input params is not nil.
func ruleFieldsSelectsPeer(namespaces *metav1.LabelSelector, pods *apisv1a.NamespacedPod,
	networks []apisv1a.CIDR, peer Peer) (bool, error) {
	switch {
	case namespaces != nil:
		return doesNamespaceSelectorMatchesPeer(namespaces, peer)
	case pods != nil:
		return doesPodsFieldMatchPeer(pods, peer)
	case networks != nil:
		return doesNetworksFieldMatchPeer(networks, peer)
	}
	return false, nil // will not get here
}

// ingressRuleSelectsPeer checks if the given AdminNetworkPolicyIngressPeer rule selects the given peer
// AdminNetworkPolicyIngressPeer defines an in-cluster peer to allow traffic from with either
// Namespaces or Pods field
func ingressRuleSelectsPeer(rulePeers []apisv1a.AdminNetworkPolicyIngressPeer, src Peer) (bool, error) {
	for i := range rulePeers {
		// 1.Validate:
		// Exactly one of the selector pointers must be set for a given peer.
		if (rulePeers[i].Namespaces == nil) == (rulePeers[i].Pods == nil) {
			return false, errors.New(alerts.OneFieldSetRulePeerErr)
		}
		fieldMatch, err := ruleFieldsSelectsPeer(rulePeers[i].Namespaces, rulePeers[i].Pods, nil, src)
		if err != nil {
			return false, err
		}
		if fieldMatch {
			return true, nil
		}
	}
	return false, nil
}

// updateConnsIfEgressRuleSelectsPeer checks if the given dst is selected by given egress rule,
// if yes, updates given policyConns with the rule's connections
func updateConnsIfEgressRuleSelectsPeer(rulePeers []apisv1a.AdminNetworkPolicyEgressPeer,
	rulePorts *[]apisv1a.AdminNetworkPolicyPort, ruleName string, dst Peer, policyConns *PolicyConnections,
	action string, isBANPrule bool) error {
	if len(rulePeers) == 0 {
		return errors.New(alerts.ANPEgressRulePeersErr)
	}
	peerSelected, err := egressRuleSelectsPeer(rulePeers, dst)
	if err != nil {
		return err
	}
	if !peerSelected {
		return nil
	}
	err = updatePolicyConns(rulePorts, ruleName, policyConns, dst, action, isBANPrule, false)
	return err
}

// updateConnsIfIngressRuleSelectsPeer checks if the given src is selected by given ingress rule,
// if yes, updates given policyConns with the rule's connections
func updateConnsIfIngressRuleSelectsPeer(rulePeers []apisv1a.AdminNetworkPolicyIngressPeer,
	rulePorts *[]apisv1a.AdminNetworkPolicyPort, ruleName string, src, dst Peer, policyConns *PolicyConnections,
	action string, isBANPrule bool) error {
	if len(rulePeers) == 0 {
		return errors.New(alerts.ANPIngressRulePeersErr)
	}
	peerSelected, err := ingressRuleSelectsPeer(rulePeers, src)
	if err != nil {
		return err
	}
	if !peerSelected {
		return nil
	}
	err = updatePolicyConns(rulePorts, ruleName, policyConns, dst, action, isBANPrule, true)
	return err
}

// updatePolicyConns gets the rule connections from the rule.ports and updates the input policy connections
// with the rule's conns considering the action
func updatePolicyConns(rulePorts *[]apisv1a.AdminNetworkPolicyPort, ruleName string, policyConns *PolicyConnections, dst Peer,
	action string, isBANPrule, isIngress bool) error {
	// get rule connections from rulePorts
	ruleConns, err := ruleConnections(rulePorts, ruleName, isBANPrule, dst, isIngress)
	if err != nil {
		return err
	}
	// update the policy conns with this rule conns
	err = policyConns.UpdateWithRuleConns(ruleConns, action, isBANPrule)
	return err
}

// ruleConnections returns the connectionSet from the current rule.Ports
//
//gocyclo:ignore
func ruleConnections(ports *[]apisv1a.AdminNetworkPolicyPort, ruleName string,
	isBANPrule bool, dst Peer, isIngress bool) (*common.ConnectionSet, error) {
	ruleKind := common.ANPRuleKind
	if isBANPrule {
		ruleKind = common.BANPRuleKind
	}
	if ports == nil { // If Ports is not set then the rule does not filter traffic via port.
		return common.MakeConnectionSetWithRule(true, ruleKind, ruleName, isIngress), nil
	}
	res := common.MakeConnectionSet(false)
	for _, anpPort := range *ports {
		if !onlyOnePortFieldsSet(anpPort) {
			return nil, errors.New(alerts.ANPPortsError)
		}
		protocol := v1.ProtocolTCP
		portSet := common.MakePortSet(false)
		switch {
		case anpPort.PortNumber != nil:
			if anpPort.PortNumber.Protocol != "" {
				protocol = anpPort.PortNumber.Protocol
			}
			portSet.AddPort(intstr.FromInt32(anpPort.PortNumber.Port), common.MakeImplyingRulesWithRule(ruleKind, ruleName, isIngress))
		case anpPort.NamedPort != nil:
			if dst == nil || isPeerRepresentative(dst) {
				// if dst is nil or representative: named port is added to the conns without conversion.
				// the protocol of a named port of an ANP rule is depending on the pod's configuration.
				// since, we have no indication of a "representative-peer" configuration, this namedPort is added as a potential
				// exposure without protocol ("").
				portSet.AddPort(intstr.FromString(*anpPort.NamedPort), common.MakeImplyingRulesWithRule(ruleKind, ruleName, isIngress))
				// In exposure analysis, in connections to entire cluster named ports cannot be resolved, and thus the protocol is unknown.
				// This is represented by a protocol with an empty name.
				res.AddConnection("", portSet)
				continue
			}
			if dst.PeerType() == IPBlockType {
				// IPblock does not have named-ports defined, warn and continue
				ruleWarnings = append(ruleWarnings, alerts.WarnNamedPortIgnoredForIP)
				continue // next port
			}
			// else - regular pod, convert the named port
			podProtocol, podPort := dst.GetPeerPod().ConvertPodNamedPort(*anpPort.NamedPort)
			if podPort == common.NoPort { // pod does not have this named port in its container
				ruleWarnings = append(ruleWarnings, alerts.WarnUnmatchedNamedPort(*anpPort.NamedPort, dst.String()))
				continue // next port
			}
			if podProtocol != "" {
				protocol = v1.Protocol(podProtocol)
			}
			portSet.AddPort(intstr.FromInt32(podPort), common.MakeImplyingRulesWithRule(ruleKind, ruleName, isIngress))
		case anpPort.PortRange != nil:
			if anpPort.PortRange.Protocol != "" {
				protocol = anpPort.PortRange.Protocol
			}
			if isEmptyPortRange(int64(anpPort.PortRange.Start), int64(anpPort.PortRange.End)) {
				// illegal: rule with empty range; (start/ end not in the legal range or end < start)
				return nil, errors.New(alerts.IllegalPortRangeError(int64(anpPort.PortRange.Start), int64(anpPort.PortRange.End)))
			}
			portSet.AddPortRange(int64(anpPort.PortRange.Start), int64(anpPort.PortRange.End), true, ruleKind, ruleName, isIngress)
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

// subjectSelectsPeer returns true iff the given subject of the (baseline)adminNetworkPolicy selects the given peer
func subjectSelectsPeer(anpSubject apisv1a.AdminNetworkPolicySubject, p Peer, errTitle string) (bool, error) {
	if (anpSubject.Namespaces == nil) == (anpSubject.Pods == nil) {
		// (Baseline)AdminNetworkPolicySubject should contain exactly one field
		// (https://github.com/kubernetes-sigs/network-policy-api/blob/v0.1.5/apis/v1alpha1/shared_types.go#L27))
		return false, errors.New(errTitle + alerts.OneFieldSetSubjectErr)
	}
	if anpSubject.Namespaces != nil {
		return doesNamespaceSelectorMatchesPeer(anpSubject.Namespaces, p)
	}
	// else: Subject.Pods is not empty (Subject.Pods contains both NamespaceSelector and PodSelector)
	return doesPodsFieldMatchPeer(anpSubject.Pods, p)
}

// anpPortContains returns if the given AdminNetworkPolicyPort selects the input connection
//
//gocyclo:ignore
func anpPortContains(rulePorts *[]apisv1a.AdminNetworkPolicyPort, protocol, port string, dst Peer) (bool, error) {
	if rulePorts == nil {
		return true, nil // If this field is empty or missing, this rule matches all ports (traffic not restricted by port)
	}
	if protocol == "" && port == "" {
		return false, nil // nothing to do
	}
	intPort, err := strconv.ParseInt(port, portBase, portBits)
	if err != nil {
		return false, err
	}
	for _, anpPort := range *rulePorts {
		if !onlyOnePortFieldsSet(anpPort) {
			return false, errors.New(fmt.Sprintf("Error in Ports : %v", anpPort) + alerts.ANPPortsError)
		}
		switch { // only one case fits
		case anpPort.PortNumber != nil:
			if doesRulePortContain(getProtocolStr(&anpPort.PortNumber.Protocol), protocol,
				int64(anpPort.PortNumber.Port), int64(anpPort.PortNumber.Port), intPort) {
				return true, nil
			}
		case anpPort.NamedPort != nil:
			if dst.PeerType() == IPBlockType {
				// IPblock does not have named-ports defined, warn and continue
				ruleWarnings = append(ruleWarnings, alerts.WarnNamedPortIgnoredForIP)
				continue // next port
			}
			podProtocol, podPort := dst.GetPeerPod().ConvertPodNamedPort(*anpPort.NamedPort)
			if podPort == common.NoPort { // pod does not have this named port in its container
				ruleWarnings = append(ruleWarnings, alerts.WarnUnmatchedNamedPort(*anpPort.NamedPort, dst.String()))
				continue // next port
			}
			if doesRulePortContain(podProtocol, protocol, int64(podPort), int64(podPort), intPort) {
				return true, nil
			}
		case anpPort.PortRange != nil:
			if isEmptyPortRange(int64(anpPort.PortRange.Start), int64(anpPort.PortRange.End)) {
				// illegal: rule with empty range; (start/ end not in the legal range or end < start)
				return false, errors.New(alerts.IllegalPortRangeError(int64(anpPort.PortRange.Start), int64(anpPort.PortRange.End)))
			}
			ruleProtocol := &anpPort.PortRange.Protocol
			if doesRulePortContain(getProtocolStr(ruleProtocol), protocol, int64(anpPort.PortRange.Start),
				int64(anpPort.PortRange.End), intPort) {
				return true, nil
			}
		}
	}
	return false, nil
}

// checkIfEgressRuleContainsConn check if the egress rule captures the given connection, if yes returns if it is passed/allowed/denied
func checkIfEgressRuleContainsConn(rulePeers []apisv1a.AdminNetworkPolicyEgressPeer, rulePorts *[]apisv1a.AdminNetworkPolicyPort, dst Peer,
	action, protocol, port string, isBANPrule bool) (res ANPRulesResult, err error) {
	if len(rulePeers) == 0 {
		return NotCaptured, errors.New(alerts.ANPEgressRulePeersErr)
	}
	peerSelected, err := egressRuleSelectsPeer(rulePeers, dst)
	if err != nil {
		return NotCaptured, err
	}
	if !peerSelected {
		return NotCaptured, nil
	}
	connSelected, err := anpPortContains(rulePorts, protocol, port, dst)
	if err != nil {
		return NotCaptured, err
	}
	if !connSelected {
		return NotCaptured, nil
	}
	// if the protocol and port are in the rulePorts, then action determines what to return
	return determineConnResByAction(action, isBANPrule)
}

// checkIfIngressRuleContainsConn check if the ingress rule captures the given connection, if yes returns if it is passed/allowed/denied
func checkIfIngressRuleContainsConn(rulePeers []apisv1a.AdminNetworkPolicyIngressPeer, rulePorts *[]apisv1a.AdminNetworkPolicyPort,
	src, dst Peer, action, protocol, port string, isBANPrule bool) (res ANPRulesResult, err error) {
	if len(rulePeers) == 0 {
		return NotCaptured, errors.New(alerts.ANPIngressRulePeersErr)
	}
	peerSelected, err := ingressRuleSelectsPeer(rulePeers, src)
	if err != nil {
		return NotCaptured, err
	}
	if !peerSelected {
		return NotCaptured, nil
	}
	connSelected, err := anpPortContains(rulePorts, protocol, port, dst)
	if err != nil {
		return NotCaptured, err
	}
	if !connSelected {
		return NotCaptured, nil
	}
	// if the protocol and port are in the rulePorts, then action determines what to return
	return determineConnResByAction(action, isBANPrule)
}

// ANPRulesResult represents the result of the anp/banp rules to a given connection
// it may be : not-captured, pass (anp only), allow or deny
type ANPRulesResult int

const (
	NotCaptured ANPRulesResult = iota
	Pass
	Allow
	Deny
)

// determineConnResByAction gets rule action that captured a connection and returns the rule res (allow, pass, deny)
func determineConnResByAction(action string, isBANPrule bool) (res ANPRulesResult, err error) {
	switch action {
	case string(apisv1a.AdminNetworkPolicyRuleActionPass):
		if isBANPrule {
			return NotCaptured, errors.New(alerts.UnknownRuleActionErr)
		}
		return Pass, nil
	case string(apisv1a.AdminNetworkPolicyRuleActionAllow):
		return Allow, nil
	case string(apisv1a.AdminNetworkPolicyRuleActionDeny):
		return Deny, nil
	default:
		return NotCaptured, errors.New(alerts.UnknownRuleActionErr)
	}
}

// isIPv6Cidr returns if the cidr is in IPv6 format
func isIPv6Cidr(cidr apisv1a.CIDR) (bool, error) {
	_, ipNet, err := net.ParseCIDR(string(cidr))
	if err != nil {
		return false, err
	}
	// if the IP is IPv6, return true
	return ipNet.IP.To4() == nil, nil
}

func (anp *AdminNetworkPolicy) fullName() string { // used for explanation goals
	return fmt.Sprintf("%s '%s'", common.ANPRuleKind, anp.Name)
}

func actionOp(action string) string { // used for explanation goals
	switch action {
	case string(apisv1a.AdminNetworkPolicyRuleActionAllow):
		return "allows"
	case string(apisv1a.BaselineAdminNetworkPolicyRuleActionDeny):
		return "denies"
	default:
		return "passes"
	}
}

func ruleExplanationStr(policyName, ruleName, action string, isIngress bool) string {
	return fmt.Sprintf("%s %s connections by %s rule %s", policyName, actionOp(action), directionName(isIngress), ruleName)
}

// rulePeersReferencedNetworks returns a list of IPBlocks representing the CIDRs referenced by the given rulePeers' Networks field.
func rulePeersReferencedIPBlocks(rulePeers []apisv1a.AdminNetworkPolicyEgressPeer) ([]*netset.IPBlock, error) {
	res := []*netset.IPBlock{}
	for _, peerObj := range rulePeers {
		if peerObj.Networks != nil {
			for _, cidr := range peerObj.Networks {
				isIPv6, err := isIPv6Cidr(cidr)
				if err != nil { // invalid cidr
					return nil, err
				}
				if isIPv6 {
					continue
				}
				ipb, err := netset.IPBlockFromCidr(string(cidr))
				if err != nil {
					return nil, err
				}
				res = append(res, ipb.Split()...)
			}
		}
	}
	return res, nil
}

// /////////////////////////////////////////////////////////////
// pre-processing computations - currently performed for exposure-analysis goals only;
// all pre-process funcs assume policies' rules are legal (rules correctness check occurs later)

// GetPolicyRulesSelectorsAndUpdateExposureClusterWideConns scans policy rules and :
// - updates policy's exposed cluster-wide connections from/to all namespaces in the cluster on ingress and egress directions
// - returns list of SingleRuleSelectors (pairs of pod and namespace selectors) from rules which have non-empty selectors,
// for which the representative peers should be generated
func (anp *AdminNetworkPolicy) GetPolicyRulesSelectorsAndUpdateExposureClusterWideConns() (rulesSelectors []SingleRuleSelectors,
	err error) {
	if anp.adminPolicyAffectsDirection(true) {
		selectors, err := anp.scanIngressRules()
		if err != nil {
			return nil, err
		}
		rulesSelectors = append(rulesSelectors, selectors...)
	}
	if anp.adminPolicyAffectsDirection(false) {
		selectors, err := anp.scanEgressRules()
		if err != nil {
			return nil, err
		}
		rulesSelectors = append(rulesSelectors, selectors...)
	}
	return rulesSelectors, nil
}

// scanIngressRules handles policy's ingress rules for updating policy's wide conns/ returning specific rules' selectors
func (anp *AdminNetworkPolicy) scanIngressRules() ([]SingleRuleSelectors, error) {
	rulesSelectors := []SingleRuleSelectors{}
	for _, rule := range anp.Spec.Ingress {
		rulePeers := rule.From
		rulePorts := rule.Ports
		selectors, err := getIngressSelectorsAndUpdateExposureClusterWideConns(rulePeers, rulePorts, string(rule.Action),
			anp.IngressPolicyClusterWideExposure)
		if err != nil {
			return nil, err
		}
		rulesSelectors = append(rulesSelectors, selectors...)
	}
	return rulesSelectors, nil
}

// scanEgressRules handles policy's egress rules for updating policy's wide conns/ returning specific rules' selectors
func (anp *AdminNetworkPolicy) scanEgressRules() ([]SingleRuleSelectors, error) {
	rulesSelectors := []SingleRuleSelectors{}
	for _, rule := range anp.Spec.Egress {
		rulePeers := rule.To
		rulePorts := rule.Ports
		selectors, err := getEgressSelectorsAndUpdateExposureClusterWideConns(rulePeers, rulePorts, string(rule.Action),
			anp.EgressPolicyClusterWideExposure)
		if err != nil {
			return nil, err
		}
		// rule with selectors selecting specific namespaces/ pods
		rulesSelectors = append(rulesSelectors, selectors...)
	}
	return rulesSelectors, nil
}

// Note that since rulePeers type is not same (different) for Ingress and Egress in (Baseline)AdminNetworkPolicy; then the following
// funcs to get the Selectors and Update the cluster-wide connection is split to :
// getEgressSelectorsAndUpdateExposureClusterWideConns and getIngressSelectorsAndUpdateExposureClusterWideConns

// getEgressSelectorsAndUpdateExposureClusterWideConns:
// loops given egress rules list:
// - if a rule have empty selectors (podSelector and namespaceSelector) or just empty namespaceSelector (nil podSelector)
// updates the cluster wide exposure of the policy
// - if a rule contains at least one defined selector : appends the rule selectors to a selector list which will be returned.
// this func assumes rules are legal (rules correctness check occurs later)
func getEgressSelectorsAndUpdateExposureClusterWideConns(rules []apisv1a.AdminNetworkPolicyEgressPeer,
	rulePorts *[]apisv1a.AdminNetworkPolicyPort, action string,
	egressPolicyClusterWideExposure *PolicyConnections) (rulesSelectors []SingleRuleSelectors, err error) {
	if len(rules) == 0 { // not valid case
		return nil, nil
	}
	for i := range rules {
		if rules[i].Networks != nil || rules[i].Nodes != nil {
			continue // not relevant to check wide-cluster exposure or get selectors from those fields
		} // else rules[i].Namespaces != nil || rules[i].Pods != nil
		ruleSel, err := getSelectorsFromNamespacesOrPodsFieldsAndUpdateExposureClusterWideConns(rules[i].Namespaces, rules[i].Pods,
			egressPolicyClusterWideExposure, rulePorts, action)
		if err != nil {
			return nil, err
		}
		if !ruleSel.isEmpty() {
			rulesSelectors = append(rulesSelectors, ruleSel)
		}
	}
	return rulesSelectors, nil
}

// getIngressSelectorsAndUpdateExposureClusterWideConns:
// loops given ingress rules list:
// - if a rule have empty selectors (podSelector and namespaceSelector)or just empty namespaceSelector (nil podSelector)
// updates the cluster wide exposure of the policy
// - if a rule contains at least one defined selector : appends the rule selectors to a selector list which will be returned.
// this func assumes rules are legal (rules correctness check occurs later)
func getIngressSelectorsAndUpdateExposureClusterWideConns(rules []apisv1a.AdminNetworkPolicyIngressPeer,
	rulePorts *[]apisv1a.AdminNetworkPolicyPort, action string,
	ingressPolicyClusterWideExposure *PolicyConnections) (rulesSelectors []SingleRuleSelectors, err error) {
	if len(rules) == 0 {
		return nil, nil
	}
	for i := range rules {
		var ruleSel SingleRuleSelectors
		ruleSel, err := getSelectorsFromNamespacesOrPodsFieldsAndUpdateExposureClusterWideConns(rules[i].Namespaces, rules[i].Pods,
			ingressPolicyClusterWideExposure, rulePorts, action)
		if err != nil {
			return nil, err
		}
		if !ruleSel.isEmpty() {
			rulesSelectors = append(rulesSelectors, ruleSel)
		}
	}
	return rulesSelectors, nil
}

// getSelectorsFromNamespacesOrPodsFieldsAndUpdateExposureClusterWideConns gets Namespaces and Pods field of an ingress/egress (B)ANP rule;
// where only one of those fields is not nil.
// checks if the rule's field selects entire-cluster, then updates the policy xgress cluster-wide exposure;
// otherwise, returns the rule's field selectors to be returned later for generating representative-peer
func getSelectorsFromNamespacesOrPodsFieldsAndUpdateExposureClusterWideConns(namespaces *metav1.LabelSelector,
	pods *apisv1a.NamespacedPod, xgressPolicyClusterWideExposure *PolicyConnections,
	rulePorts *[]apisv1a.AdminNetworkPolicyPort, action string) (ruleSel SingleRuleSelectors, err error) {
	if namespaces != nil {
		if namespaces.Size() == 0 {
			// empty Namespaces field = all cluster
			err = updateAdminNetworkPolicyExposureClusterWideConns(rulePorts, xgressPolicyClusterWideExposure, action)
			return SingleRuleSelectors{}, err
		}
		// else, the namespaces field specifies namespaces by labels
		ruleSel.NsSelector = namespaces
		return ruleSel, nil
	}
	// else - pods field should not be nil
	if pods == nil { // should not get here - added for insurance since in pre-process assuming the rules are legal
		return SingleRuleSelectors{}, nil
	}
	if doesRuleSelectAllNamespaces(&pods.NamespaceSelector, &pods.PodSelector) {
		err = updateAdminNetworkPolicyExposureClusterWideConns(rulePorts, xgressPolicyClusterWideExposure, action)
		return SingleRuleSelectors{}, err
	}
	// else selectors' combination specifies workloads by labels (at least one label is not nil and not empty)
	ruleSel.PodSelector = &pods.PodSelector
	ruleSel.NsSelector = &pods.NamespaceSelector
	return ruleSel, nil
}

// updateAdminNetworkPolicyExposureClusterWideConns updates the cluster-wide exposure connections of the (b)anp
func updateAdminNetworkPolicyExposureClusterWideConns(rulePorts *[]apisv1a.AdminNetworkPolicyPort,
	xgressPolicyClusterWideExposure *PolicyConnections, ruleAction string) error {
	// currently in exposure analysis we don't support explainability;
	// thus, we don't provide rule name info for explainability in 'ruleConnections' below.
	ruleConns, err := ruleConnections(rulePorts, "", false, nil, false)
	if err != nil {
		return err
	}
	return xgressPolicyClusterWideExposure.UpdateWithRuleConns(ruleConns, ruleAction, false)
	// note that : the last parameter sent to UpdateWithRuleConns is false, since the pre-process func assumes rules are legal
}

//////////////////////////////////////////////// ////////////////////////////////////////////////
// funcs to check if any policy-selector selects a label from the gap of two pods referencing same owner.

// ContainsLabels given input map from key to values list (each key has 2 values);
// returns first captured key from the map that the policy selectors (Subject or ruleSelectors) uses with at least one of those values
//
// i.e. returns non-empty key if:
// - there is a labelSelector with matchLabels: {<key>: <val_in_gap>} (contains a key:val from the input map)
// - there is a selector with matchExpression with values list (operator not Exist/ DoesNotExist) that contains only one of the gap-values
//
//nolint:dupl // AdminNetworkPolicy and BaselineAdminNetworkPolicy are not same object - this func will be removed on enhancement
func (anp *AdminNetworkPolicy) ContainsLabels(ownerNs *Namespace, diffLabels map[string][]string) (key, selectorStr string) {
	// first check the policy's Subject
	// if the subject contains only namespaces field; i.e it selects all pods in the namespace	- no problem
	if anp.Spec.Subject.Namespaces == nil && anp.Spec.Subject.Pods != nil {
		if key, selectorStr := podsFieldContainsDiffLabel(anp.Spec.Subject.Pods, ownerNs, diffLabels); key != "" {
			return key, selectorStr
		}
	}

	//  loop egress rules selectors
	if anp.adminPolicyAffectsDirection(false) {
		if key, egressSel := anp.egressRulesContainGapLabel(ownerNs, diffLabels); key != "" {
			return key, egressSel
		}
	}
	// loop ingress rules selectors
	if anp.adminPolicyAffectsDirection(true) {
		if key, ingressSel := anp.ingressRulesContainGapLabel(ownerNs, diffLabels); key != "" {
			return key, ingressSel
		}
	}
	return "", ""
}

func (anp *AdminNetworkPolicy) egressRulesContainGapLabel(ownerNs *Namespace, diffLabels map[string][]string) (key, selector string) {
	for _, rule := range anp.Spec.Egress {
		rulePeers := rule.To
		if key, selector = egressRulePeerContainsGapLabel(rulePeers, ownerNs, diffLabels); key != "" {
			return key, selector
		}
	}
	return "", ""
}

func (anp *AdminNetworkPolicy) ingressRulesContainGapLabel(ownerNs *Namespace, diffLabels map[string][]string) (key, selector string) {
	for _, rule := range anp.Spec.Ingress {
		rulePeers := rule.From
		if key, selector = ingressRulePeerContainsGapLabel(rulePeers, ownerNs, diffLabels); key != "" {
			return key, selector
		}
	}
	return "", ""
}

func podsFieldContainsDiffLabel(podsField *apisv1a.NamespacedPod, ownerNs *Namespace, diffLabels map[string][]string) (key,
	selector string) {
	// check first the namespaceSelector
	nsSelector, _ := metav1.LabelSelectorAsSelector(&podsField.NamespaceSelector) // assuming correctness,
	if !nsSelector.Matches(labels.Set(ownerNs.Labels)) {                          // ns selector does not select the owner's ns
		return "", ""
	}
	// ns selector matches owner namespace, check if podSelector contains gap labels
	if key, selectorStr := selectorContainsGapLabel(&podsField.PodSelector, diffLabels); key != "" {
		return key, selectorStr
	}
	return "", ""
}

func egressRulePeerContainsGapLabel(rulePeers []apisv1a.AdminNetworkPolicyEgressPeer, ownerNs *Namespace,
	diffLabels map[string][]string) (key, selector string) {
	for _, rule := range rulePeers {
		// if rule contains namespaces - continue : no problem
		if rule.Namespaces != nil {
			continue
		}
		// pods field is used - check if matches ownerNs and contains pod-selectors from the gap
		if key, selector := podsFieldContainsDiffLabel(rule.Pods, ownerNs, diffLabels); key != "" {
			return key, selector
		}
	}
	return "", ""
}

func ingressRulePeerContainsGapLabel(rulePeers []apisv1a.AdminNetworkPolicyIngressPeer, ownerNs *Namespace,
	diffLabels map[string][]string) (key, selector string) {
	for _, rule := range rulePeers {
		// if rule contains namespaces - continue : no problems
		if rule.Namespaces != nil {
			continue
		}
		// pods field is used - check if matches ownerNs and contains pod-selectors from the gap
		if key, selector := podsFieldContainsDiffLabel(rule.Pods, ownerNs, diffLabels); key != "" {
			return key, selector
		}
	}
	return "", ""
}
