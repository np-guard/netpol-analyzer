/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	v1 "k8s.io/api/core/v1"

	"github.com/np-guard/models/pkg/interval"
)

// ConnectionSet represents a set of allowed connections between two peers on a k8s env
// and implements Connection interface
type ConnectionSet struct {
	AllowAll         bool
	AllowedProtocols map[v1.Protocol]*PortSet // map from protocol name to set of allowed ports
}

var allProtocols = []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP, v1.ProtocolSCTP}

// MakeConnectionSet returns a pointer to ConnectionSet object with all connections or no connections
func MakeConnectionSet(all bool) *ConnectionSet {
	if all {
		return &ConnectionSet{AllowAll: true, AllowedProtocols: map[v1.Protocol]*PortSet{}}
	}
	return &ConnectionSet{AllowedProtocols: map[v1.Protocol]*PortSet{}}
}

// Intersection updates ConnectionSet object to be the intersection result with other ConnectionSet
func (conn *ConnectionSet) Intersection(other *ConnectionSet) {
	if other.AllowAll {
		return
	}
	if conn.AllowAll {
		conn.AllowAll = false
		for protocol, ports := range other.AllowedProtocols {
			conn.AllowedProtocols[protocol] = ports.Copy()
		}
		return
	}
	for protocol := range conn.AllowedProtocols {
		otherPorts, ok := other.AllowedProtocols[protocol]
		if !ok {
			delete(conn.AllowedProtocols, protocol)
		} else {
			conn.AllowedProtocols[protocol].Intersection(otherPorts)
			if conn.AllowedProtocols[protocol].IsEmpty() {
				delete(conn.AllowedProtocols, protocol)
			}
		}
	}
}

// IsEmpty returns true if the ConnectionSet has no allowed connections
func (conn *ConnectionSet) IsEmpty() bool {
	return !conn.AllowAll && len(conn.AllowedProtocols) == 0
}

func (conn *ConnectionSet) isAllConnectionsWithoutAllowAll() bool {
	if conn.AllowAll {
		return false
	}
	for _, protocol := range allProtocols {
		ports, ok := conn.AllowedProtocols[protocol]
		if !ok {
			return false
		} else if !ports.IsAll() {
			return false
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

// Union updates ConnectionSet object to be the union result with other ConnectionSet
func (conn *ConnectionSet) Union(other *ConnectionSet) {
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
			conn.AllowedProtocols[protocol].Union(otherPorts)
		}
	}
	for protocol := range other.AllowedProtocols {
		if _, ok := conn.AllowedProtocols[protocol]; !ok {
			portsCopy := other.AllowedProtocols[protocol].Copy()
			conn.AllowedProtocols[protocol] = portsCopy
		}
	}
	conn.checkIfAllConnections()
}

// Subtract : updates current ConnectionSet object with the result of
// subtracting other ConnectionSet from current ConnectionSet
func (conn *ConnectionSet) Subtract(other *ConnectionSet) {
	if other.IsEmpty() { // nothing to subtract
		return
	}
	if other.AllowAll { // subtract everything
		conn.AllowAll = false
		conn.AllowedProtocols = map[v1.Protocol]*PortSet{}
		return
	}
	if conn.AllowAll {
		conn.AllowAll = false // we are about to subtract something
		conn.addAllConns()
	}
	for protocol, ports := range conn.AllowedProtocols {
		if otherPorts, ok := other.AllowedProtocols[protocol]; ok {
			if ports.Equal(otherPorts) {
				delete(conn.AllowedProtocols, protocol)
			} else {
				ports.subtract(otherPorts)
				if conn.AllowedProtocols[protocol].IsEmpty() {
					delete(conn.AllowedProtocols, protocol)
				}
			}
		}
	}
}

// addAllConns : add all possible connections to the current ConnectionSet's allowed protocols
func (conn *ConnectionSet) addAllConns() {
	for _, protocol := range allProtocols {
		conn.AddConnection(protocol, MakePortSet(true))
	}
}

// Contains returns true if the input port+protocol is an allowed connection
func (conn *ConnectionSet) Contains(port, protocol string) bool {
	intPort, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	if conn.AllowAll {
		return true
	}
	for allowedProtocol, allowedPorts := range conn.AllowedProtocols {
		if strings.EqualFold(protocol, string(allowedProtocol)) {
			return allowedPorts.Contains(int64(intPort))
		}
	}
	return false
}

// ContainedIn returns true if current ConnectionSet is conatained in the input ConnectionSet object
func (conn *ConnectionSet) ContainedIn(other *ConnectionSet) bool {
	if other.AllowAll {
		return true
	}
	if conn.AllowAll {
		return false
	}
	for protocol, ports := range conn.AllowedProtocols {
		otherPorts, ok := other.AllowedProtocols[protocol]
		if !ok {
			return false
		}
		if !ports.ContainedIn(otherPorts) {
			return false
		}
	}
	return true
}

// AddConnection updates current ConnectionSet object with new allowed connection
func (conn *ConnectionSet) AddConnection(protocol v1.Protocol, ports *PortSet) {
	if ports.IsEmpty() {
		return
	}
	connPorts, ok := conn.AllowedProtocols[protocol]
	if ok {
		connPorts.Union(ports)
	} else {
		conn.AllowedProtocols[protocol] = ports.Copy()
	}
}

// String returns a string representation of the ConnectionSet object
func (conn *ConnectionSet) String() string {
	if conn.AllowAll {
		return allConnsStr
	} else if conn.IsEmpty() {
		return noConnsStr
	}
	resStrings := []string{}
	for protocol, ports := range conn.AllowedProtocols {
		resStrings = append(resStrings, protocolAndPortsStr(protocol, ports.String()))
	}
	sort.Strings(resStrings)
	return strings.Join(resStrings, ",")
}

// Equal returns true if the current ConnectionSet object is equal to the input object
func (conn *ConnectionSet) Equal(other *ConnectionSet) bool {
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
		if !ports.Equal(otherPorts) {
			return false
		}
	}
	return true
}

// portRange implements the PortRange interface
type portRange struct {
	Interval interval.Interval
}

func (p *portRange) Start() int64 {
	return p.Interval.Start()
}

func (p *portRange) End() int64 {
	return p.Interval.End()
}

func (p *portRange) String() string {
	if p.Interval.End() != p.Interval.Start() {
		return fmt.Sprintf("%d-%d", p.Start(), p.End())
	}
	return fmt.Sprintf("%d", p.Start())
}

// ProtocolsAndPortsMap() returns a map from allowed protocol to list of allowed ports ranges.
func (conn *ConnectionSet) ProtocolsAndPortsMap() map[v1.Protocol][]PortRange {
	res := make(map[v1.Protocol][]PortRange, 0)
	for protocol, portSet := range conn.AllowedProtocols {
		res[protocol] = make([]PortRange, 0)
		// TODO: consider leave the slice of ports empty if portSet covers the full range
		for _, v := range portSet.Ports.Intervals() {
			res[protocol] = append(res[protocol], &portRange{Interval: v})
		}
	}
	return res
}

// AllConnections returns true if all ports are allowed for all protocols
func (conn *ConnectionSet) AllConnections() bool {
	return conn.AllowAll
}

const (
	connsAndPortRangeSeparator = ","
	allConnsStr                = "All Connections"
	noConnsStr                 = "No Connections"
	complemetPrefix            = "All but: "
	empty                      = "Empty"
)

func ConnStrFromConnProperties(allProtocolsAndPorts bool, protocolsAndPorts map[v1.Protocol][]PortRange) string {
	if allProtocolsAndPorts {
		return allConnsStr
	}
	if len(protocolsAndPorts) == 0 {
		return noConnsStr
	}
	var connStr string
	// connStrings will contain the string of given conns protocols and ports as is
	connStrings := make([]string, len(protocolsAndPorts))
	// connAsComplementStr will contain the conns' as "All but" + conns complement to the All conns
	connAsComplementStr := make([]string, 0)
	index := 0
	for protocol, ports := range protocolsAndPorts {
		connStrings[index] = protocolAndPortsStr(protocol, portsString(ports))
		index++
		// complement conn string
		complementPortsStr := getComplementPorts(ports)
		if complementPortsStr == empty || complementPortsStr == "" { // ports is full range
			continue
		}
		connAsComplementStr = append(connAsComplementStr, protocolAndPortsStr(protocol, complementPortsStr))
	}
	sort.Strings(connStrings)
	sort.Strings(connAsComplementStr)
	connStr = strings.Join(connStrings, connsAndPortRangeSeparator)
	complementStr := complemetPrefix + strings.Join(connAsComplementStr, connsAndPortRangeSeparator)
	// return the shorter string as the representation
	if len(complementStr) < len(connStr) {
		return complementStr
	}
	return connStr
}

// getComplementPorts computes and returns string representation of the complement intervals of given ports
func getComplementPorts(ports []PortRange) string {
	// create canonicalSet with all possible port ranges
	complementCanonicalSet := interval.New(minPort, maxPort).ToSet()
	// loop ports and subtract them from the full canonicalSet to get the complement
	for i := range ports {
		currCanonicalSet := (ports[i].(*portRange).Interval).ToSet()
		complementCanonicalSet = complementCanonicalSet.Subtract(currCanonicalSet)
	}
	return complementCanonicalSet.String()
}

// get string representation for a list of port ranges
func portsString(ports []PortRange) string {
	portsStr := make([]string, len(ports))
	for i := range ports {
		portsStr[i] = ports[i].String()
	}
	return strings.Join(portsStr, connsAndPortRangeSeparator)
}

func protocolAndPortsStr(protocol v1.Protocol, ports string) string {
	return string(protocol) + " " + ports
}
