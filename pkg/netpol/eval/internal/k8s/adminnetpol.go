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

	pkgcommmon "github.com/np-guard/netpol-analyzer/pkg/internal/common"
	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
	"github.com/np-guard/netpol-analyzer/pkg/logger"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/alerts"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// AdminNetworkPolicy is an alias for k8s adminNetworkPolicy object
type AdminNetworkPolicy struct {
	*apisv1a.AdminNetworkPolicy                 // embedding k8s admin-network-policy object
	warnings                    common.Warnings // set of warnings which are raised by the anp
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
		err := updateConnsIfIngressRuleSelectsPeer(rulePeers, rulePorts, src, dst, res, string(rule.Action), false)
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
		err := updateConnsIfEgressRuleSelectsPeer(rulePeers, rulePorts, dst, res, string(rule.Action), false)
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
	return anp.Spec.Priority >= pkgcommmon.MinANPPriority && anp.Spec.Priority <= pkgcommmon.MaxANPPriority
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

func (anp *AdminNetworkPolicy) LogWarnings(l logger.Logger) {
	anp.warnings.LogPolicyWarnings(l)
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

// doesNetworksFieldMatchPeer checks if the given peer matches the networks field.
// returns true if the peer's IPBlock is contained within any of the cidr-s in networks field
func doesNetworksFieldMatchPeer(networks []apisv1a.CIDR, peer Peer) (bool, error) {
	if peer.GetPeerIPBlock() == nil {
		return false, nil // networks field selects peers via CIDR blocks (IPs).
		// nothing to do with Peer type which is not IPBlock
	}
	for _, cidr := range networks {
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
			return false, errors.New(netpolerrors.InvalidCIDRAddr)
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
			return false, errors.New(netpolerrors.OneFieldSetRulePeerErr)
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
		return doesNamespacesFieldMatchPeer(namespaces, peer)
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
			return false, errors.New(netpolerrors.OneFieldSetRulePeerErr)
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
	rulePorts *[]apisv1a.AdminNetworkPolicyPort, dst Peer, policyConns *PolicyConnections, action string, isBANPrule bool) error {
	if len(rulePeers) == 0 {
		return errors.New(netpolerrors.ANPEgressRulePeersErr)
	}
	peerSelected, err := egressRuleSelectsPeer(rulePeers, dst)
	if err != nil {
		return err
	}
	if !peerSelected {
		return nil
	}
	err = updatePolicyConns(rulePorts, policyConns, dst, action, isBANPrule)
	return err
}

// updateConnsIfIngressRuleSelectsPeer checks if the given src is selected by given ingress rule,
// if yes, updates given policyConns with the rule's connections
func updateConnsIfIngressRuleSelectsPeer(rulePeers []apisv1a.AdminNetworkPolicyIngressPeer,
	rulePorts *[]apisv1a.AdminNetworkPolicyPort, src, dst Peer, policyConns *PolicyConnections, action string, isBANPrule bool) error {
	if len(rulePeers) == 0 {
		return errors.New(netpolerrors.ANPIngressRulePeersErr)
	}
	peerSelected, err := ingressRuleSelectsPeer(rulePeers, src)
	if err != nil {
		return err
	}
	if !peerSelected {
		return nil
	}
	err = updatePolicyConns(rulePorts, policyConns, dst, action, isBANPrule)
	return err
}

// updatePolicyConns gets the rule connections from the rule.ports and updates the input policy connections
// with the rule's conns considering the action
func updatePolicyConns(rulePorts *[]apisv1a.AdminNetworkPolicyPort, policyConns *PolicyConnections, dst Peer,
	action string, isBANPrule bool) error {
	// get rule connections from rulePorts
	ruleConns, err := ruleConnections(rulePorts, dst)
	if err != nil {
		return err
	}
	// update the policy conns with this rule conns
	err = policyConns.UpdateWithRuleConns(ruleConns, action, isBANPrule)
	return err
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
			if podProtocol != "" {
				protocol = v1.Protocol(podProtocol)
			}
			portSet.AddPort(intstr.FromInt32(podPort))
		case anpPort.PortRange != nil:
			if anpPort.PortRange.Protocol != "" {
				protocol = anpPort.PortRange.Protocol
			}
			if isEmptyPortRange(int64(anpPort.PortRange.Start), int64(anpPort.PortRange.End)) {
				// illegal: rule with empty range; (start/ end not in the legal range or end < start)
				return nil, errors.New(alerts.IllegalPortRangeError(int64(anpPort.PortRange.Start), int64(anpPort.PortRange.End)))
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

// subjectSelectsPeer returns true iff the given subject of the (baseline)adminNetworkPolicy selects the given peer
func subjectSelectsPeer(anpSubject apisv1a.AdminNetworkPolicySubject, p Peer, errTitle string) (bool, error) {
	if (anpSubject.Namespaces == nil) == (anpSubject.Pods == nil) {
		// (Baseline)AdminNetworkPolicySubject should contain exactly one field
		// (https://github.com/kubernetes-sigs/network-policy-api/blob/v0.1.5/apis/v1alpha1/shared_types.go#L27))
		return false, errors.New(errTitle + netpolerrors.OneFieldSetSubjectErr)
	}
	if anpSubject.Namespaces != nil {
		return doesNamespacesFieldMatchPeer(anpSubject.Namespaces, p)
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
			return false, errors.New(fmt.Sprintf("Error in Ports : %v", anpPort) + netpolerrors.ANPPortsError)
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
		return NotCaptured, errors.New(netpolerrors.ANPEgressRulePeersErr)
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
		return NotCaptured, errors.New(netpolerrors.ANPIngressRulePeersErr)
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
			return NotCaptured, errors.New(netpolerrors.UnknownRuleActionErr)
		}
		return Pass, nil
	case string(apisv1a.AdminNetworkPolicyRuleActionAllow):
		return Allow, nil
	case string(apisv1a.AdminNetworkPolicyRuleActionDeny):
		return Deny, nil
	default:
		return NotCaptured, errors.New(netpolerrors.UnknownRuleActionErr)
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
