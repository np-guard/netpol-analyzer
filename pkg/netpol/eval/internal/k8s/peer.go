// Copyright 2022
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package k8s

import (
	"github.com/np-guard/models/pkg/ipblock"
	"k8s.io/apimachinery/pkg/types"
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
	if p.Pod.FakePod {
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

////////////////////////////////////////////////////

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
