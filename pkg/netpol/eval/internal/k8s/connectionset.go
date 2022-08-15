// Copyright 2022
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package k8s

import (
	"sort"
	"strconv"
	"strings"

	v1 "k8s.io/api/core/v1"
)

type ConnectionSet struct {
	AllowAll         bool
	AllowedProtocols map[v1.Protocol]*PortSet //map from protocol name to set of allowed ports
}

func MakeConnectionSet(all bool) ConnectionSet {
	if all {
		return ConnectionSet{AllowAll: true, AllowedProtocols: map[v1.Protocol]*PortSet{}}
	}
	return ConnectionSet{AllowedProtocols: map[v1.Protocol]*PortSet{}}
}

func (conn *ConnectionSet) Intersection(other ConnectionSet) {
	if other.AllowAll {
		return
	}
	if conn.AllowAll {
		conn.AllowAll = false
		for protocol, ports := range other.AllowedProtocols {
			portsCopy := ports.Copy()
			conn.AllowedProtocols[protocol] = &portsCopy
		}
		return
	}
	for protocol := range conn.AllowedProtocols {
		otherPorts, ok := other.AllowedProtocols[protocol]
		if !ok {
			delete(conn.AllowedProtocols, protocol)
		} else {
			conn.AllowedProtocols[protocol].Intersection(*otherPorts)
			if conn.AllowedProtocols[protocol].IsEmpty() {
				delete(conn.AllowedProtocols, protocol)
			}
		}
	}
}

func (conn *ConnectionSet) IsEmpty() bool {
	return !conn.AllowAll && len(conn.AllowedProtocols) == 0
}

func (conn *ConnectionSet) isAllConnectionsWithoutAllowAll() bool {
	if conn.AllowAll {
		return false
	}
	allProtocols := []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP, v1.ProtocolSCTP}
	for _, protocol := range allProtocols {
		ports, ok := conn.AllowedProtocols[protocol]
		if !ok {
			return false
		} else {
			if !ports.IsAll() {
				return false
			}
		}
	}

	return true
}

func (conn *ConnectionSet) checkIfAllConnections() {
	if conn.isAllConnectionsWithoutAllowAll() {
		conn.AllowAll = true
		conn.AllowedProtocols = map[v1.Protocol]*PortSet{}
	}
}

func (conn *ConnectionSet) Union(other ConnectionSet) {
	if conn.AllowAll || other.IsEmpty() {
		return
	}
	if other.AllowAll {
		conn.AllowAll = true
		conn.AllowedProtocols = map[v1.Protocol]*PortSet{}
		return
	}
	for protocol := range conn.AllowedProtocols {
		if otherPorts, ok := other.AllowedProtocols[protocol]; ok {
			conn.AllowedProtocols[protocol].Union(*otherPorts)
		}
	}
	for protocol := range other.AllowedProtocols {
		if _, ok := conn.AllowedProtocols[protocol]; !ok {
			portsCopy := other.AllowedProtocols[protocol].Copy()
			conn.AllowedProtocols[protocol] = &portsCopy
		}
	}
	conn.checkIfAllConnections()
}

func (conn *ConnectionSet) Contains(port, protocol string) bool {
	intPort, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	//strings.ToUpper(protocol)
	for allowedProtocol, allowedPorts := range conn.AllowedProtocols {
		if strings.ToUpper(protocol) == string(allowedProtocol) {
			return allowedPorts.Contains((int64)(intPort))
		}
	}
	return false
}

func (conn *ConnectionSet) ContainedIn(other ConnectionSet) bool {
	if other.AllowAll {
		return true
	}
	if conn.AllowAll {
		return false
	}
	for protocol, ports := range conn.AllowedProtocols {

		other_ports, ok := other.AllowedProtocols[protocol]
		if !ok {
			return false
		}
		if !ports.ContainedIn(*other_ports) {
			return false
		}
	}
	return true
}

func (conn *ConnectionSet) AddConnection(protocol v1.Protocol, ports PortSet) {
	if ports.IsEmpty() {
		return
	}
	connPorts, ok := conn.AllowedProtocols[protocol]
	if ok {
		connPorts.Union(ports)
	} else {
		conn.AllowedProtocols[protocol] = &ports
	}
}

func (conn *ConnectionSet) String() string {
	if conn.AllowAll {
		return "All Connections"
	} else if conn.IsEmpty() {
		return "No Connections"
	}
	resStrings := []string{}
	for protocol, ports := range conn.AllowedProtocols {
		resStrings = append(resStrings, string(protocol)+" "+ports.String())
	}
	sort.Strings(resStrings)
	return strings.Join(resStrings[:], ",")
}

func (conn *ConnectionSet) Equal(other ConnectionSet) bool {
	if conn.AllowAll != other.AllowAll {
		return false
	}
	if len(conn.AllowedProtocols) != len(other.AllowedProtocols) {
		return false
	}
	for protocol, ports := range conn.AllowedProtocols {
		otherPorts, ok := other.AllowedProtocols[protocol]
		if !ok {
			return false
		}
		if !ports.Equal(*otherPorts) {
			return false
		}
	}
	return true
}
