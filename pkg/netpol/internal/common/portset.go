/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"reflect"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	NoPort        = -1
	minPort int64 = 1
	maxPort int64 = 65535
)

type NamedPortsType map[string]ImplyingRulesType

func portNames(ports NamedPortsType) []string {
	res := []string{}
	for p := range ports {
		res = append(res, p)
	}
	return res
}

// PortSet: represents set of allowed ports in a connection
type PortSet struct {
	Ports *AugmentedCanonicalSet // ports, augmented with implying rules data (used for explainability)
	// NamedPorts/ExcludedNamedPorts is a map from a port name to implying rule names (used for explainnability)
	// When not running with explainability, existing (excluded)named ports will be represented by a mapping
	// from a port name to an empty implying rules holder
	NamedPorts         NamedPortsType
	ExcludedNamedPorts NamedPortsType
}

// MakePortSet: return a new PortSet object, with all ports or no ports allowed
func MakePortSet(all bool) *PortSet {
	return &PortSet{Ports: NewAugmentedCanonicalSet(minPort, maxPort, all),
		NamedPorts:         NamedPortsType{},
		ExcludedNamedPorts: NamedPortsType{},
	}
}

func MakeAllPortSetWithImplyingRules(rules ImplyingRulesType) *PortSet {
	return &PortSet{Ports: NewFullAugmentedSetWithRules(minPort, maxPort, rules),
		NamedPorts:         NamedPortsType{},
		ExcludedNamedPorts: NamedPortsType{},
	}
}

// Equal: return true if current object equals another PortSet object
func (p *PortSet) Equal(other *PortSet) bool {
	return p.Ports.Equal(other.Ports) && reflect.DeepEqual(portNames(p.NamedPorts), portNames(other.NamedPorts)) &&
		reflect.DeepEqual(portNames(p.ExcludedNamedPorts), portNames(other.ExcludedNamedPorts))
}

// IsEmpty: return true if current PortSet is semantically empty (no ports allowed)
func (p *PortSet) IsEmpty() bool {
	return p.Ports.IsEmpty() && len(p.NamedPorts) == 0
}

// Unfilled: return true if current PortSet is syntactically empty
func (p *PortSet) IsUnfilled() bool {
	return p.Ports.IsUnfilled() && len(p.NamedPorts) == 0
}

// Copy: return a new copy of a PortSet object
func (p *PortSet) Copy() *PortSet {
	res := MakePortSet(false)
	res.Ports = p.Ports.Copy()
	for k, v := range p.NamedPorts {
		res.NamedPorts[k] = v.Copy()
	}
	for k, v := range p.ExcludedNamedPorts {
		res.ExcludedNamedPorts[k] = v.Copy()
	}
	return res
}

func (p *PortSet) ClearPorts() {
	p.Ports.ClearInSet()
	p.NamedPorts = NamedPortsType{}
	p.ExcludedNamedPorts = NamedPortsType{}
}

// AddPort: update current PortSet object with new added port as allowed
func (p *PortSet) AddPort(port intstr.IntOrString, implyingRules ImplyingRulesType) {
	if port.Type == intstr.String {
		if _, ok := p.NamedPorts[port.StrVal]; !ok {
			p.NamedPorts[port.StrVal] = MakeImplyingRules()
		}
		p.NamedPorts[port.StrVal].Union(implyingRules)
		delete(p.ExcludedNamedPorts, port.StrVal)
	} else {
		p.Ports.AddAugmentedInterval(NewAugmentedIntervalWithRules(int64(port.IntVal), int64(port.IntVal), true, implyingRules))
	}
}

// RemovePort: update current PortSet object with removing input port from allowed ports
func (p *PortSet) RemovePort(port intstr.IntOrString) {
	if port.Type == intstr.String {
		p.ExcludedNamedPorts[port.StrVal] = p.NamedPorts[port.StrVal]
		delete(p.NamedPorts, port.StrVal)
	} else {
		p.Ports.AddAugmentedInterval(NewAugmentedInterval(int64(port.IntVal), int64(port.IntVal), false))
	}
}

// AddPortRange: update current PortSet object with new added port range as allowed
func (p *PortSet) AddPortRange(minPort, maxPort int64, inSet bool, fromRule string, isIngress bool) {
	p.Ports.AddAugmentedInterval(NewAugmentedIntervalWithRule(minPort, maxPort, inSet, fromRule, isIngress))
}

// Union: update current PortSet object with union of input PortSet object
// Note: this function is not symmetrical regarding the update of implying rules:
// it updates implying rules of 'p' by those of 'other' only for ports that get changed in 'p'
func (p *PortSet) Union(other *PortSet) {
	p.Ports = p.Ports.Union(other.Ports)
	// union current namedPorts with other namedPorts, and delete other namedPorts from current excludedNamedPorts
	for k, v := range other.NamedPorts {
		if _, ok := p.NamedPorts[k]; !ok {
			// this named port was not in p --> take implying rules from other
			p.NamedPorts[k] = v.Copy()
		}
		delete(p.ExcludedNamedPorts, k)
	}
	// add excludedNamedPorts from other to current excludedNamedPorts if they are not in united p.NamedPorts
	for k, v := range other.ExcludedNamedPorts {
		if _, ok := p.NamedPorts[k]; !ok {
			if _, ok := p.ExcludedNamedPorts[k]; !ok {
				// this exluded named port was not excluded in p --> take implying rules from other
				p.ExcludedNamedPorts[k] = v.Copy()
			}
		}
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

const comma = ","

// String: return string representation of current PortSet
func (p *PortSet) String() string {
	res := p.Ports.String()
	if len(p.NamedPorts) > 0 {
		sortedNamedPorts := p.GetNamedPortsKeys()
		sort.Strings(sortedNamedPorts)
		if res != "" {
			res += comma
		}
		res += strings.Join(sortedNamedPorts, comma)
	}
	return res
}

// Contains: return true if current PortSet contains a specific input port
func (p *PortSet) Contains(port int64) bool {
	return p.Ports.Contains(port)
}

// GetNamedPorts returns the named ports of the current PortSet
func (p *PortSet) GetNamedPorts() NamedPortsType {
	return p.NamedPorts
}

// GetNamedPortsKeys returns the named ports names of the current PortSet
func (p *PortSet) GetNamedPortsKeys() []string {
	res := make([]string, len(p.NamedPorts))
	index := 0
	for k := range p.NamedPorts {
		res[index] = k
		index++
	}
	return res
}

// subtract: updates current portSet with the result of subtracting the given portSet from it
func (p *PortSet) subtract(other *PortSet) {
	p.Ports = p.Ports.Subtract(other.Ports)
	// delete other named ports from current portSet's named ports map
	// and add the deleted named ports to excluded named ports map
	for k, v := range other.NamedPorts {
		if _, ok := p.ExcludedNamedPorts[k]; !ok {
			p.ExcludedNamedPorts[k] = MakeImplyingRules()
		}
		p.ExcludedNamedPorts[k].Union(v.Copy())
		delete(p.NamedPorts, k)
	}
}

func (p *PortSet) GetEquivalentCanonicalPortSet() *PortSet {
	res := p.Copy()
	res.Ports = p.Ports.GetEquivalentCanonicalAugmentedSet()
	return res
}
