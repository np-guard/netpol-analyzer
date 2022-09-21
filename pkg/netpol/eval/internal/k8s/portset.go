package k8s

import (
	"reflect"

	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	minPort int64 = 1
	maxPort int64 = 65535
)

// PortSet: represents set of allowed ports in a connection
type PortSet struct {
	Ports              CanonicalIntervalSet
	NamedPorts         map[string]bool
	ExcludedNamedPorts map[string]bool
}

// MakePortSet: return a new PortSet object, with all ports or no ports allowed
func MakePortSet(all bool) PortSet {
	if all {
		portsInterval := Interval{Start: minPort, End: maxPort}
		return PortSet{Ports: CanonicalIntervalSet{IntervalSet: []Interval{portsInterval}}}
	}
	return PortSet{}
}

// Equal: return true if current object equals another PortSet object
func (p *PortSet) Equal(other PortSet) bool {
	return p.Ports.Equal(other.Ports) && reflect.DeepEqual(p.NamedPorts, other.NamedPorts) &&
		reflect.DeepEqual(p.ExcludedNamedPorts, other.ExcludedNamedPorts)
}

// IsEmpty: return true if current object is empty (no ports allowed)
func (p *PortSet) IsEmpty() bool {
	return p.Ports.IsEmpty() && len(p.NamedPorts) == 0
}

// Copy: return a new copy of a PortSet object
func (p *PortSet) Copy() PortSet {
	res := PortSet{}
	res.Ports = p.Ports.Copy()
	for k, v := range p.NamedPorts {
		res.NamedPorts[k] = v
	}
	for k, v := range p.ExcludedNamedPorts {
		res.ExcludedNamedPorts[k] = v
	}
	return res
}

// AddPort: update current PortSet object with new added port as allowed
func (p *PortSet) AddPort(port intstr.IntOrString) {
	if port.Type == intstr.String {
		p.NamedPorts[port.StrVal] = true
		delete(p.ExcludedNamedPorts, port.StrVal)
	} else {
		p.Ports.AddInterval(Interval{Start: int64(port.IntVal), End: int64(port.IntVal)})
	}
}

// RemovePort: update current PortSet object with removing input port from allowed ports
func (p *PortSet) RemovePort(port intstr.IntOrString) {
	if port.Type == intstr.String {
		delete(p.NamedPorts, port.StrVal)
		p.ExcludedNamedPorts[port.StrVal] = true
	} else {
		p.Ports.AddHole(Interval{Start: int64(port.IntVal), End: int64(port.IntVal)})
	}
}

// AddPortRange: update current PortSet object with new added port range as allowed
func (p *PortSet) AddPortRange(minPort, maxPort int64) {
	p.Ports.AddInterval(Interval{Start: minPort, End: maxPort})
}

// Union: update current PortSet object with union of input PortSet object
func (p *PortSet) Union(other PortSet) {
	p.Ports.Union(other.Ports)
	for k, v := range other.NamedPorts {
		p.NamedPorts[k] = v
	}
	for k, v := range other.ExcludedNamedPorts {
		p.ExcludedNamedPorts[k] = v
	}
}

// ContainedIn: return true if current PortSet object is contained in input PortSet object
func (p *PortSet) ContainedIn(other PortSet) bool {
	return p.Ports.ContainedIn(other.Ports)
}

// Intersection: update current PortSet object as intersection with input PortSet object
func (p *PortSet) Intersection(other PortSet) {
	p.Ports.Intersection(other.Ports)
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
	portObj := PortSet{}
	portObj.AddPortRange(port, port)
	return portObj.ContainedIn(*p)
}

/*
func (p *PortSet) Subtract(other PortSet){

}
*/
