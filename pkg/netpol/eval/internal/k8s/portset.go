package k8s

import (
	"reflect"

	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	minPort int64 = 1
	maxPort int64 = 65535
)

type PortSet struct {
	Ports              CanonicalIntervalSet
	NamedPorts         map[string]bool
	ExcludedNamedPorts map[string]bool
}

func MakePortSet(all bool) PortSet {
	if all {
		portsInterval := Interval{Start: minPort, End: maxPort}
		return PortSet{Ports: CanonicalIntervalSet{IntervalSet: []Interval{portsInterval}}}
	}
	return PortSet{}
}

func (p *PortSet) Equal(other PortSet) bool {
	return p.Ports.Equal(other.Ports) && reflect.DeepEqual(p.NamedPorts, other.NamedPorts) &&
		reflect.DeepEqual(p.ExcludedNamedPorts, other.ExcludedNamedPorts)
}

func (p *PortSet) IsEmpty() bool {
	return p.Ports.IsEmpty() && len(p.NamedPorts) == 0
}

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

func (p *PortSet) AddPort(port intstr.IntOrString) {
	if port.Type == intstr.String {
		p.NamedPorts[port.StrVal] = true
		delete(p.ExcludedNamedPorts, port.StrVal)
	} else {
		p.Ports.AddInterval(Interval{Start: int64(port.IntVal), End: int64(port.IntVal)})
	}
}

func (p *PortSet) RemovePort(port intstr.IntOrString) {
	if port.Type == intstr.String {
		delete(p.NamedPorts, port.StrVal)
		p.ExcludedNamedPorts[port.StrVal] = true
	} else {
		p.Ports.AddHole(Interval{Start: int64(port.IntVal), End: int64(port.IntVal)})
	}
}

func (p *PortSet) AddPortRange(minPort, maxPort int64) {
	p.Ports.AddInterval(Interval{Start: minPort, End: maxPort})
}

func (p *PortSet) Union(other PortSet) {
	p.Ports.Union(other.Ports)
	for k, v := range other.NamedPorts {
		p.NamedPorts[k] = v
	}
	for k, v := range other.ExcludedNamedPorts {
		p.ExcludedNamedPorts[k] = v
	}
}

func (p *PortSet) ContainedIn(other PortSet) bool {
	return p.Ports.ContainedIn(other.Ports)
}

func (p *PortSet) Intersection(other PortSet) {
	p.Ports.Intersection(other.Ports)
}

func (p *PortSet) IsAll() bool {
	return p.Equal(MakePortSet(true))
}

func (p *PortSet) String() string {
	return p.Ports.String()
}

func (p *PortSet) Contains(port int64) bool {
	portObj := PortSet{}
	portObj.AddPortRange(port, port)
	return portObj.ContainedIn(*p)
}

/*
func (p *PortSet) Subtract(other PortSet){

}
*/
