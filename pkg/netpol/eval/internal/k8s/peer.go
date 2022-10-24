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

// PeerType is a type to indicate the type of a Peer object (Pod / Workload / IP address)
type PeerType int

const (
	PodType PeerType = iota
	WorkloadType
	Iptype
)

// Peer represents a k8s pod / workload / ip address
type Peer struct {
	PeerType  PeerType // PodType or Iptype
	IP        string
	Pod       *Pod
	Workload  *Workload
	Namespace *Namespace
}

// GetPeerNamespace: get peer's namespace
func (p *Peer) GetPeerNamespace() string {
	if p.Namespace != nil {
		return p.Namespace.Name
	}
	return ""
}

// getPeerLabels: get peer's labels
func (p *Peer) getPeerLabels() map[string]string {
	if p.PeerType == PodType {
		return p.Pod.Labels
	}
	if p.PeerType == WorkloadType {
		return p.Workload.Labels
	}
	return map[string]string{}
}
