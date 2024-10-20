/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package k8s

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

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

// why could not success yet with
// using generics to avoid duplicates in following two funcs `egressRuleSelectsPeer` and `ingressRuleSelectsPeer`:
// (same for updateConnsIfEgressRuleSelectsPeer and updateConnsIfIngressRuleSelectsPeer)
//
// according to https://tip.golang.org/doc/go1.18#generics :
// "The Go compiler does not support accessing a struct field x.f where x is of type parameter type even if all types in the type
// parameter’s type set have a field f. We may remove this restriction in a future release."
// till GO 1.21 this restriction is not removed yet.
// for example:
// replacing "func egressRuleSelectsPeer(rulePeers []apisv1a.AdminNetworkPolicyEgressPeer, dst Peer) (bool, error)" and
//           "func ingressRuleSelectsPeer(rulePeers []apisv1a.AdminNetworkPolicyIngressPeer, src Peer) (bool, error)"
//
// with a func using generics like this :
//   "func xgressRuleSelectsPeer[T apisv1a.AdminNetworkPolicyEgressPeer | apisv1a.AdminNetworkPolicyIngressPeer](rulePeers []T,
//                             dst Peer) (bool, error)"
// will fail with errors such as :
//                  "rulePeers[i].Namespaces undefined (type T has no field or method Namespaces)"
//
// a useful way to skip the errors is to define an interface with some Getter funcs to be implemented on the "inheriting types"
// of the parameters.
// but in this case : since our parameters are not of local types, we can not define new methods (like getters) on them;
// not even with using aliases since then we'll need to copy values in calling funcs into the aliases and
// this is not more efficient than current solutions.
//
// @todo: if GO is upgraded to a release that does not has this restriction on types with same fields, replace following two "duplicated"
// funcs with one func that uses generics type

// egressRuleSelectsPeer checks if the given []AdminNetworkPolicyEgressPeer rule selects the given peer
// currently supposing a single egressPeer rule may contain only Namespaces/ Pods Fields,
// @todo support also egress rule peer with Networks field
// @todo if egress rule peer contains Nodes field, raise a warning that we don't support it
func egressRuleSelectsPeer(rulePeers []apisv1a.AdminNetworkPolicyEgressPeer, dst Peer) (bool, error) {
	for i := range rulePeers {
		fieldMatch, err := ruleFieldsSelectsPeer(rulePeers[i].Namespaces, rulePeers[i].Pods, dst)
		if err != nil {
			return false, err
		}
		if fieldMatch {
			return true, nil
		}
	}
	return false, nil
}

// ruleFieldsSelectsPeer returns wether the input rule fields selects the peer
func ruleFieldsSelectsPeer(namespaces *metav1.LabelSelector, pods *apisv1a.NamespacedPod, peer Peer) (bool, error) {
	// only one field in a rule `apisv1a.AdminNetworkPolicyEgressPeer` or `apisv1a.AdminNetworkPolicyIngressPeer` may be not nil (set)
	if (namespaces == nil) == (pods == nil) {
		return false, errors.New(netpolerrors.OneFieldSetRulePeerErr)
	}
	fieldMatch := false
	var err error
	if namespaces != nil {
		fieldMatch, err = doesNamespacesFieldMatchPeer(namespaces, peer)
	} else { // else Pods is not nil
		fieldMatch, err = doesPodsFieldMatchPeer(pods, peer)
	}
	if err != nil {
		return false, err
	}
	return fieldMatch, nil
}

// ingressRuleSelectsPeer checks if the given AdminNetworkPolicyIngressPeer rule selects the given peer
func ingressRuleSelectsPeer(rulePeers []apisv1a.AdminNetworkPolicyIngressPeer, src Peer) (bool, error) {
	for i := range rulePeers {
		fieldMatch, err := ruleFieldsSelectsPeer(rulePeers[i].Namespaces, rulePeers[i].Pods, src)
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
			podProtocol, podPort := dst.GetPeerPod().ConvertPodNamedPort(*anpPort.NamedPort)
			if podPort == common.NoPort { // pod does not have this named port in its container
				continue // @todo should raise a warning
			}
			if podProtocol != "" {
				protocol = v1.Protocol(podProtocol)
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

// subjectSelectsPeer returns true iff the given subject of the (baseline)adminNetworkPolicy selects the given peer
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

// anpPortContains returns if the given AdminNetworkPolicyPort selects the input connection
//
//nolint:gosec // memory aliasing in for loop is to fit an old func
//gocyclo:ignore
func anpPortContains(rulePorts *[]apisv1a.AdminNetworkPolicyPort, protocol, port string, dst Peer) (bool, error) {
	if rulePorts == nil {
		return true, nil // If this field is empty or missing, this rule matches all ports (traffic not restricted by port)
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
			if strings.ToUpper(protocol) != getProtocolStr(&anpPort.PortNumber.Protocol) {
				continue
			}
			if int64(anpPort.PortNumber.Port) == intPort {
				return true, nil
			}
		case anpPort.NamedPort != nil:
			podProtocol, podPort := dst.GetPeerPod().ConvertPodNamedPort(*anpPort.NamedPort)
			if !strings.EqualFold(protocol, podProtocol) {
				continue
			}
			if int64(podPort) == intPort {
				return true, nil
			}
		case anpPort.PortRange != nil:
			ruleProtocol := &anpPort.PortRange.Protocol
			if strings.ToUpper(protocol) != getProtocolStr(ruleProtocol) {
				continue
			}
			if isEmptyPortRange(anpPort.PortRange.Start, anpPort.PortRange.End) {
				return false, nil
			}
			if intPort >= int64(anpPort.PortRange.Start) && intPort <= int64(anpPort.PortRange.End) {
				return true, nil
			}
		}
	}
	return false, nil
}

// checkIfEgressRuleContainsConn check if the egress rule captures the given connection, if yes returns if it is passed/allowed/denied
func checkIfEgressRuleContainsConn(rulePeers []apisv1a.AdminNetworkPolicyEgressPeer, rulePorts *[]apisv1a.AdminNetworkPolicyPort, dst Peer,
	action, protocol, port string, isBANPrule bool) (res int, captured bool, err error) {
	if len(rulePeers) == 0 {
		return 0, false, errors.New(netpolerrors.ANPEgressRulePeersErr)
	}
	peerSelected, err := egressRuleSelectsPeer(rulePeers, dst)
	if err != nil {
		return 0, false, err
	}
	if !peerSelected {
		return 0, false, nil
	}
	connSelected, err := anpPortContains(rulePorts, protocol, port, dst)
	if err != nil {
		return 0, false, err
	}
	if !connSelected {
		return 0, false, nil
	}
	// if the protocol and port are in the rulePorts, then action determines what to return
	return determineConnResByAction(action, isBANPrule)
}

// checkIfIngressRuleContainsConn check if the ingress rule captures the given connection, if yes returns if it is passed/allowed/denied
func checkIfIngressRuleContainsConn(rulePeers []apisv1a.AdminNetworkPolicyIngressPeer, rulePorts *[]apisv1a.AdminNetworkPolicyPort,
	src, dst Peer, action, protocol, port string, isBANPrule bool) (res int, captured bool, err error) {
	if len(rulePeers) == 0 {
		return 0, false, errors.New(netpolerrors.ANPIngressRulePeersErr)
	}
	peerSelected, err := ingressRuleSelectsPeer(rulePeers, src)
	if err != nil {
		return 0, false, err
	}
	if !peerSelected {
		return 0, false, nil
	}
	connSelected, err := anpPortContains(rulePorts, protocol, port, dst)
	if err != nil {
		return 0, false, err
	}
	if !connSelected {
		return 0, false, nil
	}
	// if the protocol and port are in the rulePorts, then action determines what to return
	return determineConnResByAction(action, isBANPrule)
}

const (
	Pass = iota
	Allow
	Deny
)

// determineConnResByAction gets rule action that captured a connection and returns the rule res (allow, pass, deny)
func determineConnResByAction(action string, isBANPrule bool) (res int, captured bool, err error) {
	switch action {
	case string(apisv1a.AdminNetworkPolicyRuleActionPass):
		if isBANPrule {
			return -1, false, errors.New(netpolerrors.UnknownRuleActionErr)
		}
		return Pass, true, nil
	case string(apisv1a.AdminNetworkPolicyRuleActionAllow):
		return Allow, true, nil
	case string(apisv1a.AdminNetworkPolicyRuleActionDeny):
		return Deny, true, nil
	default:
		return -1, false, errors.New(netpolerrors.UnknownRuleActionErr)
	}
}

////////////////////////////////////////////////////////////////////////////////////////////

// AdminNetworkPolicy is an alias for k8s adminNetworkPolicy object
type AdminNetworkPolicy apisv1a.AdminNetworkPolicy

// note that could not use Generics with GO 1.21 or older versions; since:
// according to https://tip.golang.org/doc/go1.18#generics :
// "The Go compiler does not support accessing a struct field x.f where x is of type parameter type even if all types in the type
// parameter’s type set have a field f. We may remove this restriction in a future release."
// (till GO 1.21 this restriction is not removed yet.)
// and to resolve remaining duplicated code for AdminNetworkPolicy and BaselineAdminNetworkPolicy we need the option of using
// the inner fields of  generic type in the funcs, either implicitly or explicitly.
// @todo: with upgraded GO version, check if using generics may help avoid remaining duplicates in
// the files adminnetpol.go and baseline_admin_netpol.go

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
func (anp *AdminNetworkPolicy) GetIngressPolicyConns(src, dst Peer) (*PolicyConnections, error) {
	res := InitEmptyPolicyConnections()
	for _, rule := range anp.Spec.Ingress { // rule is apisv1a.AdminNetworkPolicyIngressRule
		rulePeers := rule.From
		rulePorts := rule.Ports
		if err := updateConnsIfIngressRuleSelectsPeer(rulePeers, rulePorts, src, dst, res, string(rule.Action), false); err != nil {
			return nil, anp.anpRuleErr(rule.Name, err.Error())
		}
	}
	return res, nil
}

// GetEgressPolicyConns returns the connections from the egress rules selecting the dst in spec of the adminNetworkPolicy
func (anp *AdminNetworkPolicy) GetEgressPolicyConns(dst Peer) (*PolicyConnections, error) {
	res := InitEmptyPolicyConnections()
	for _, rule := range anp.Spec.Egress { // rule is apisv1a.AdminNetworkPolicyEgressRule
		rulePeers := rule.To
		rulePorts := rule.Ports
		if err := updateConnsIfEgressRuleSelectsPeer(rulePeers, rulePorts, dst, res, string(rule.Action), false); err != nil {
			return nil, anp.anpRuleErr(rule.Name, err.Error())
		}
	}
	return res, nil
}

const (
	// according to this: https://network-policy-api.sigs.k8s.io/api-overview/#adminnetworkpolicy-priorities
	// The Priority field in the ANP spec is defined as an integer value within the range 0 to 1000
	minPriority = 0
	maxPriority = 1000
)

// HasValidPriority returns if the priority in a valid range
func (anp *AdminNetworkPolicy) HasValidPriority() bool {
	// note: k8s defines "1000" as the maximum numeric value for priority
	// but openshift currently only support priority values between 0 and 99
	// current implementation satisfies k8s requirement
	return anp.Spec.Priority >= minPriority && anp.Spec.Priority <= maxPriority
}

// CheckEgressConnAllowed checks if the input conn is allowed/passed/denied or not captured on egress
func (anp *AdminNetworkPolicy) CheckEgressConnAllowed(dst Peer, protocol, port string) (res int, captured bool, err error) {
	for _, rule := range anp.Spec.Egress {
		rulePeers := rule.To
		rulePorts := rule.Ports
		ruleRes, captured, err := checkIfEgressRuleContainsConn(rulePeers, rulePorts, dst, string(rule.Action), protocol, port, false)
		if err != nil {
			return 0, false, anp.anpRuleErr(rule.Name, err.Error())
		}
		if !captured {
			continue
		}
		return ruleRes, captured, nil
	}
	// getting here means the protocol+port was not captured
	return Pass, false, nil
}

// CheckIngressConnAllowed checks if the input conn is allowed/passed/denied or not captured on ingress
func (anp *AdminNetworkPolicy) CheckIngressConnAllowed(src, dst Peer, protocol, port string) (res int, captured bool, err error) {
	for _, rule := range anp.Spec.Ingress {
		rulePeers := rule.From
		rulePorts := rule.Ports
		ruleRes, captured, err := checkIfIngressRuleContainsConn(rulePeers, rulePorts, src, dst, string(rule.Action), protocol, port, false)
		if err != nil {
			return 0, false, anp.anpRuleErr(rule.Name, err.Error())
		}
		if !captured {
			continue
		}
		return ruleRes, captured, nil
	}
	// getting here means the protocol+port was not captured
	return Pass, false, nil
}
