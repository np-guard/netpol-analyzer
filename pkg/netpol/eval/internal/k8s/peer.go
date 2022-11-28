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
	"k8s.io/apimachinery/pkg/types"
)

// PeerType is a type to indicate the type of a Peer object (Pod or IP address)
type PeerType int

const (
	PodType PeerType = iota
	IPBlockType
)

// Peer represents a k8s pod or an ip address
type Peer struct {
	PeerType  PeerType
	IPBlock   *IPBlock // a set of intervals for ip addresses ranges
	Pod       *Pod
	Namespace *Namespace
}

func IsIPType(inputType PeerType) bool {
	return inputType == IPBlockType
}

func (p *Peer) String() string {
	if p.PeerType == PodType {
		//pod type
		return types.NamespacedName{Name: p.Pod.Name, Namespace: p.Pod.Namespace}.String()
	}
	//IPBlockType
	return p.IPBlock.ToIPRanges()
}
