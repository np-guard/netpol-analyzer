/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package k8s

import (
	"k8s.io/apimachinery/pkg/types"

	"github.com/np-guard/models/pkg/netset"
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
	GetPeerIPBlock() *netset.IPBlock
}

// PodPeer implements k8s.Peer interface and eval.Peer interface
type PodPeer struct {
	Pod             *Pod
	NamespaceObject *Namespace
}

// IPBlockPeer implements k8s.Peer interface and eval.Peer interface
type IPBlockPeer struct {
	IPBlock *netset.IPBlock
}

// WorkloadPeer implements eval.Peer interface
type WorkloadPeer struct {
	Pod *Pod
}

const podKind = "Pod"

// A WorkloadPeer with kind == RepresentativePeer is a representativePeer
// a representative peer is a peer inferred from a policy rule (selectors), not a parsed pod/deployment object
// and is used to represent a potential pod/ns entity in the cluster (that does not exist on the input resources)
// but may have permitted connectivity to input resources (pods/deployments) based on input network policies.
const RepresentativePodName = "representative-pod"
const RepresentativePeerKind = "RepresentativePeer"

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
	if p.Pod.IsPodRepresentative() {
		return RepresentativePeerKind
	}
	ownerKind := p.Pod.Owner.Kind
	if ownerKind == "" { // no owner -- workload is a Pod
		return podKind
	}
	return ownerKind
}

// this func is not expected to be used for WorkloadPeer with kind == RepresentativePeer
func (p *WorkloadPeer) String() string {
	if p.Pod.FakePod { // ingress-controller or representative-pod
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

func (p *PodPeer) GetPeerIPBlock() *netset.IPBlock {
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

func (p *IPBlockPeer) GetPeerIPBlock() *netset.IPBlock {
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
