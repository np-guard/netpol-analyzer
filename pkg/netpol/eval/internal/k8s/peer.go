/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package k8s

import (
	"k8s.io/apimachinery/pkg/types"

	"github.com/np-guard/models/pkg/ipblock"
)

// PeerType is a type to indicate the type of a Peer object (Pod or IP address)
type PeerType int

const (
	PodType PeerType = iota
	IPBlockType
)

// Peer represents a k8s pod or an ip address
type Peer interface {
	// PeerType returns the PeerType of the Peer object
	PeerType() PeerType
	// String returns a string representation of the Peer object
	String() string
	// GetPeerPod returns a reference to the Pod object of the peer if it is a pod, else returns nil
	GetPeerPod() *Pod
	// GetPeerNamespace returns a reference to Namespace object of the peer's namespace if it is a pod,
	// else returns nil
	GetPeerNamespace() *Namespace
	// GetPeerIPBlock returns a reference to IPBlock if the peer is IP address, else returns nil
	GetPeerIPBlock() *ipblock.IPBlock
}

// PodPeer implements k8s.Peer interface and eval.Peer interface
type PodPeer struct {
	Pod             *Pod
	NamespaceObject *Namespace
}

// IPBlockPeer implements k8s.Peer interface and eval.Peer interface
type IPBlockPeer struct {
	IPBlock *ipblock.IPBlock
}

// WorkloadPeer implements eval.Peer interface
type WorkloadPeer struct {
	Pod *Pod
}

// RepresentativePeer implements eval.Peer interface
// a representative peer is a peer inferred from a policy rule (selector) not a parsed pod/deployment object
// and is used to represent a potential pod/ns entity in the cluster (that does not exist on the input resources)
// but may have enabled connectivity to input resources (pods/deployments) based on input network policies.
type RepresentativePeer struct {
	// Pod is a fake pod originated as following:
	// - if inferred from a policy rule, which contains only non-empty namespaceSelector; the pod's namespace is a fake namespace
	// with the labels from the selector (those labels also stored in PotentialNamespaceLabels)
	// - if inferred from a policy rule, which contains only podSelector; the pod's namespace is same as the policy's namespace;
	// and its labels are taken from the selector labels
	// - if inferred from selector combining a namespaceSelector and a podSelector: the pod's labels will contain the podSelector labels
	// and its namespace is a fake namespace with the namespaceSelector labels  (those labels also stored in PotentialNamespaceLabels)
	Pod                      *Pod
	PotentialNamespaceLabels map[string]string
	// HasUnusualNsLabels indicates if the potential namespace labels set of the representative peer contains any labels inferred
	// from a selector with matchExpression with operator:NotIn, Exists, DoesNotExist - which require special handling
	HasUnusualNsLabels bool
}

const podKind = "Pod"

// //////////////////////////////////////////////////
func (p *WorkloadPeer) Name() string {
	ownerName := p.Pod.Owner.Name
	if ownerName == "" {
		return p.Pod.Name // no owner - workload is a Pod
	}
	return ownerName
}

func (p *WorkloadPeer) Namespace() string {
	return p.Pod.Namespace
}

func (p *WorkloadPeer) Kind() string {
	ownerKind := p.Pod.Owner.Kind
	if ownerKind == "" { // no owner -- workload is a Pod
		return podKind
	}
	return ownerKind
}

func (p *WorkloadPeer) String() string {
	if p.Pod.FakePod { // ingress-controller
		return "{" + p.Pod.Name + "}"
	}
	return types.NamespacedName{Name: p.Name(), Namespace: p.Namespace()}.String() + "[" + p.Kind() + "]"
}

func (p *WorkloadPeer) IP() string {
	return ""
}

func (p *WorkloadPeer) IsPeerIPType() bool {
	return false
}

// //////////////////////////////////////////////////

const RepresentativePodName = "representative-pod"
const representativePodKind = "RepresentativePod"

func (p *RepresentativePeer) Name() string {
	return p.Pod.Name
}

func (p *RepresentativePeer) Namespace() string {
	return p.Pod.Namespace
}

func (p *RepresentativePeer) Kind() string {
	return representativePodKind
}

func (p *RepresentativePeer) String() string {
	return types.NamespacedName{Name: p.Name(), Namespace: p.Namespace()}.String()
}

func (p *RepresentativePeer) IP() string {
	return ""
}

func (p *RepresentativePeer) IsPeerIPType() bool {
	return false
}

// //////////////////////////////////////////////////

func (p *PodPeer) PeerType() PeerType {
	return PodType
}

func (p *PodPeer) String() string {
	return types.NamespacedName{Name: p.Pod.Name, Namespace: p.Pod.Namespace}.String()
}

func (p *PodPeer) GetPeerPod() *Pod {
	return p.Pod
}

func (p *PodPeer) GetPeerNamespace() *Namespace {
	return p.NamespaceObject
}

func (p *PodPeer) GetPeerIPBlock() *ipblock.IPBlock {
	return nil
}

func (p *PodPeer) Name() string {
	return p.Pod.Name
}

func (p *PodPeer) Namespace() string {
	return p.Pod.Namespace
}

func (p *PodPeer) IP() string {
	return ""
}

func (p *PodPeer) IsPeerIPType() bool {
	return false
}

func (p *PodPeer) Kind() string {
	return podKind
}

////////////////////////////////////////////////////

func (p *IPBlockPeer) PeerType() PeerType {
	return IPBlockType
}

func (p *IPBlockPeer) String() string {
	return p.IPBlock.ToIPRanges()
}

func (p *IPBlockPeer) GetPeerPod() *Pod {
	return nil
}

func (p *IPBlockPeer) GetPeerNamespace() *Namespace {
	return nil
}

func (p *IPBlockPeer) GetPeerIPBlock() *ipblock.IPBlock {
	return p.IPBlock
}

func (p *IPBlockPeer) Name() string {
	return ""
}

func (p *IPBlockPeer) Namespace() string {
	return ""
}

func (p *IPBlockPeer) IP() string {
	return p.String()
}

func (p *IPBlockPeer) IsPeerIPType() bool {
	return true
}

func (p *IPBlockPeer) Kind() string {
	return ""
}
