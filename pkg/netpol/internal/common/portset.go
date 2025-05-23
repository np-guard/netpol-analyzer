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
	MinPort int64 = 1
	MaxPort int64 = 65535
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
	return &PortSet{Ports: NewAugmentedCanonicalSet(MinPort, MaxPort, all),
		NamedPorts:         NamedPortsType{},
		ExcludedNamedPorts: NamedPortsType{},
	}
}

func MakeAllPortSetWithImplyingRules(rules ImplyingRulesType) *PortSet {
	return &PortSet{Ports: NewAugmentedCanonicalSetWithRules(MinPort, MaxPort, true, rules),
		NamedPorts:         NamedPortsType{},
		ExcludedNamedPorts: NamedPortsType{},
	}
}

func MakeEmptyPortSetWithImplyingRules(rules ImplyingRulesType) *PortSet {
	return &PortSet{Ports: NewAugmentedCanonicalSetWithRules(MinPort, MaxPort, false, rules),
		NamedPorts:         NamedPortsType{},
		ExcludedNamedPorts: NamedPortsType{},
	}
}

func (p *PortSet) RemoveDefaultRule(isIngress bool) {
	p.Ports.RemoveDefaultRule(isIngress)
}

func (p *PortSet) CleanImplyingRules() {
	p.Ports.CleanImplyingRules()
}

// Equal: return true if current object equals another PortSet object
// Ports are equal if they have same allowed port-numbers and same allowed named-ports
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

// AddPort: update current PortSet object with new added port as allowed
func (p *PortSet) AddPort(port intstr.IntOrString, implyingRules ImplyingRulesType) {
	if port.Type == intstr.String {
		if _, ok := p.NamedPorts[port.StrVal]; !ok {
			p.NamedPorts[port.StrVal] = InitImplyingRules()
		}
		p.NamedPorts[port.StrVal] = p.NamedPorts[port.StrVal].Update(implyingRules, false, NeverCollectRules)
		delete(p.ExcludedNamedPorts, port.StrVal)
	} else {
		p.Ports.AddAugmentedInterval(NewAugmentedIntervalWithRules(int64(port.IntVal), int64(port.IntVal),
			true, implyingRules), NeverCollectRules)
	}
}

// RemovePort: update current PortSet object with removing input port from allowed ports
func (p *PortSet) RemovePort(port intstr.IntOrString) {
	if port.Type == intstr.String {
		p.ExcludedNamedPorts[port.StrVal] = p.NamedPorts[port.StrVal]
		delete(p.NamedPorts, port.StrVal)
	} else {
		p.Ports.AddAugmentedInterval(NewAugmentedInterval(int64(port.IntVal), int64(port.IntVal), false), NeverCollectRules)
	}
}

// ReplaceNamedPort: add the given numerical port and remove its corresponding named port (without adding to ExcludedNamedPorts)
func (p *PortSet) ReplaceNamedPort(namedPort string, portNum intstr.IntOrString, implyingRules ImplyingRulesType) {
	p.AddPort(portNum, implyingRules)
	delete(p.NamedPorts, namedPort)
}

// AddPortRange: update current PortSet object with new added port range as allowed
func (p *PortSet) AddPortRange(minPort, maxPort int64, inSet bool, ruleKind, fromRule string, isIngress bool) {
	p.Ports.AddAugmentedInterval(NewAugmentedIntervalWithRule(minPort, maxPort, inSet, ruleKind, fromRule, isIngress), NeverCollectRules)
}

// Union: update current PortSet object with union of input PortSet object
// Note: this function is not symmetrical regarding the update of implying rules:
//   - for ports that get changed in 'p', it overrides implying rules of 'p' by those of 'other';
//   - for unchanged ports it updates implying rules of 'p' according to 'collectSameInclusionRules'
//     (collecting when true, overriding by priority otherwise)
func (p *PortSet) Union(other *PortSet, collectSameInclusionRules bool) {
	p.Ports = p.Ports.Union(other.Ports, collectSameInclusionRules)
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
			p.ExcludedNamedPorts[k] = InitImplyingRules()
		}
		p.ExcludedNamedPorts[k] = p.ExcludedNamedPorts[k].Update(v, false, NeverCollectRules)
		delete(p.NamedPorts, k)
	}
}

func (p *PortSet) GetEquivalentCanonicalPortSet() *PortSet {
	res := p.Copy()
	res.Ports = p.Ports.GetEquivalentCanonicalAugmentedSet()
	return res
}
