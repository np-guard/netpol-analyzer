/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"reflect"

	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/np-guard/models/pkg/interval"
)

const (
	minPort int64 = 1
	maxPort int64 = 65535
)

// PortSet: represents set of allowed ports in a connection
type PortSet struct {
	Ports              *interval.CanonicalSet
	NamedPorts         map[string]bool
	ExcludedNamedPorts map[string]bool
}

// MakePortSet: return a new PortSet object, with all ports or no ports allowed
func MakePortSet(all bool) *PortSet {
	if all {
		return &PortSet{Ports: interval.New(minPort, maxPort).ToSet()}
	}
	return &PortSet{Ports: interval.NewCanonicalSet()}
}

// Equal: return true if current object equals another PortSet object
func (p *PortSet) Equal(other *PortSet) bool {
	return p.Ports.Equal(other.Ports) && reflect.DeepEqual(p.NamedPorts, other.NamedPorts) &&
		reflect.DeepEqual(p.ExcludedNamedPorts, other.ExcludedNamedPorts)
}

// IsEmpty: return true if current object is empty (no ports allowed)
func (p *PortSet) IsEmpty() bool {
	return p.Ports.IsEmpty() && len(p.NamedPorts) == 0
}

// Copy: return a new copy of a PortSet object
func (p *PortSet) Copy() *PortSet {
	res := PortSet{}
	res.Ports = p.Ports.Copy()
	for k, v := range p.NamedPorts {
		res.NamedPorts[k] = v
	}
	for k, v := range p.ExcludedNamedPorts {
		res.ExcludedNamedPorts[k] = v
	}
	return &res
}

// AddPort: update current PortSet object with new added port as allowed
func (p *PortSet) AddPort(port intstr.IntOrString) {
	if port.Type == intstr.String {
		p.NamedPorts[port.StrVal] = true
		delete(p.ExcludedNamedPorts, port.StrVal)
	} else {
		p.Ports.AddInterval(interval.New(int64(port.IntVal), int64(port.IntVal)))
	}
}

// RemovePort: update current PortSet object with removing input port from allowed ports
func (p *PortSet) RemovePort(port intstr.IntOrString) {
	if port.Type == intstr.String {
		delete(p.NamedPorts, port.StrVal)
		p.ExcludedNamedPorts[port.StrVal] = true
	} else {
		p.Ports.AddHole(interval.New(int64(port.IntVal), int64(port.IntVal)))
	}
}

// AddPortRange: update current PortSet object with new added port range as allowed
func (p *PortSet) AddPortRange(minPort, maxPort int64) {
	p.Ports.AddInterval(interval.New(minPort, maxPort))
}

// Union: update current PortSet object with union of input PortSet object
func (p *PortSet) Union(other *PortSet) {
	p.Ports = p.Ports.Union(other.Ports)
	for k, v := range other.NamedPorts {
		p.NamedPorts[k] = v
	}
	for k, v := range other.ExcludedNamedPorts {
		p.ExcludedNamedPorts[k] = v
	}
}

// ContainedIn: return true if current PortSet object is contained in input PortSet object
func (p *PortSet) ContainedIn(other *PortSet) bool {
	return p.Ports.ContainedIn(other.Ports)
}

// Intersection: update current PortSet object as intersection with input PortSet object
func (p *PortSet) Intersection(other *PortSet) {
	p.Ports = p.Ports.Intersect(other.Ports)
}

// IsAll: return true if current PortSet object contains all ports
func (p *PortSet) IsAll() bool {
	return p.Equal(MakePortSet(true))
}

// String: return string representation of current PortSet
func (p *PortSet) String() string {
	return p.Ports.String()
}

// Contains: return true if current PortSet contains a specific input port
func (p *PortSet) Contains(port int64) bool {
	return p.Ports.Contains(port)
}

// subtract: updates current portSet with the result of subtracting the given portSet from it
func (p *PortSet) subtract(other *PortSet) {
	p.Ports = p.Ports.Subtract(other.Ports)
	p.subtractNamedPorts(other.NamedPorts)
}

// subtractNamedPorts: deletes given named ports from current portSet's named ports map
// and adds the deleted named ports to excluded named ports map
func (p *PortSet) subtractNamedPorts(otherNamedPorts map[string]bool) {
	for namedPort := range otherNamedPorts {
		delete(p.NamedPorts, namedPort)
		p.ExcludedNamedPorts[namedPort] = true
	}
}
