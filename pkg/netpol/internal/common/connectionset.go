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
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/np-guard/models/pkg/interval"
)

// ConnectionSet represents a set of allowed connections between two peers on a k8s env
// and implements Connection interface
// The explainability information is represented as follows: every PortSet (in AllowedProtocols)
// includes information about implying rules for every range.
// CommonImplyingRules contain implying rules for empty or full ConectionSet (when AllowedProtocols is empty)
// The following variant should hold: CommonImplyingRules not empty <==> AllowedProtocols empty
type ConnectionSet struct {
	AllowAll            bool
	AllowedProtocols    map[v1.Protocol]*PortSet // map from protocol name to set of allowed ports
	CommonImplyingRules *ImplyingRulesType       // used for explainability, when AllowedProtocols is empty (i.e., all allowed or all denied)
}

var allProtocols = []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP, v1.ProtocolSCTP}

// MakeConnectionSet returns a pointer to ConnectionSet object with all connections or no connections
func MakeConnectionSet(all bool) *ConnectionSet {
	if all {
		return &ConnectionSet{AllowAll: true, AllowedProtocols: map[v1.Protocol]*PortSet{}, CommonImplyingRules: &ImplyingRulesType{}}
	}
	return &ConnectionSet{AllowedProtocols: map[v1.Protocol]*PortSet{}, CommonImplyingRules: &ImplyingRulesType{}}
}

// Add common implying rule, i.e., a rule that is relevant for the whole ConnectionSet
func (conn *ConnectionSet) AddCommonImplyingRule(implyingRule string) {
	conn.CommonImplyingRules.AddRule(implyingRule)
}

func (conn *ConnectionSet) GetEquivalentCanonicalConnectionSet() *ConnectionSet {
	res := MakeConnectionSet(false)
	if conn.AllowAll {
		res.AllowAll = true
		return res
	}
	for protocol, ports := range conn.AllowedProtocols {
		canonicalPorts := ports.GetEquivalentCanonicalPortSet()
		if !canonicalPorts.IsEmpty() {
			res.AllowedProtocols[protocol] = canonicalPorts
		}
	}
	return res
}

// GetAllTCPConnections returns a pointer to ConnectionSet object with all TCP protocol connections
func GetAllTCPConnections() *ConnectionSet {
	tcpConn := MakeConnectionSet(false)
	tcpConn.AddConnection(v1.ProtocolTCP, MakePortSet(true))
	return tcpConn
}

// Intersection updates ConnectionSet object to be the intersection result with other ConnectionSet
func (conn *ConnectionSet) Intersection(other *ConnectionSet) {
	if conn.IsEmpty() {
		return // nothing changes
	}
	if other.IsEmpty() && len(other.AllowedProtocols) == 0 {
		// a special case when we should replace current common implying rules by others'
		conn.CommonImplyingRules = other.CommonImplyingRules.Copy()
		conn.AllowAll = false
		conn.AllowedProtocols = map[v1.Protocol]*PortSet{}
		return
	}

	if len(conn.AllowedProtocols) == 0 && len(other.AllowedProtocols) == 0 {
		// conn.AllowAll && other.AllowAll should be true
		// a special case when we should union common implying rules
		conn.CommonImplyingRules.Union(other.CommonImplyingRules)
		return
	}
	if conn.AllowAll {
		// prepare conn for the intersection - we need to seep implying rules info into all protocols/ports
		conn.rebuildAllowAllExplicitly()
	}
	if other.AllowAll {
		// prepare other for the intersection - we need to seep implying rules info into all protocols/ports
		other.rebuildAllowAllExplicitly()
	}
	conn.AllowAll = false
	for protocol := range conn.AllowedProtocols {
		otherPorts, ok := other.AllowedProtocols[protocol]
		if !ok {
			// we do not remove empty PortSets, we keep the ImplyingRules info for explainability
			conn.AllowedProtocols[protocol].ClearPorts()
		} else {
			conn.AllowedProtocols[protocol].Intersection(otherPorts)
		}
	}
	conn.updateIfAllConnections() // the result may be AllowAll if both conn and other were AllowAll
}

// IsEmpty returns true if the ConnectionSet has no allowed connections
func (conn *ConnectionSet) IsEmpty() bool {
	if conn.AllowAll {
		return false
	}
	if len(conn.AllowedProtocols) == 0 {
		return true
	}
	// now check semantically
	for _, ports := range conn.AllowedProtocols {
		if !ports.IsEmpty() { // this is a semantic emptiness check (no included ports, may be holes)
			return false
		}
	}
	return true
}

func (conn *ConnectionSet) updateIfAllConnections() {
	if conn.AllowAll {
		return
	}
	for _, protocol := range allProtocols {
		ports, ok := conn.AllowedProtocols[protocol]
		if !ok {
			return
		} else if !ports.IsAll() {
			return
		}
	}
	conn.AllowAll = true
	// we keep conn.AllowedProtocols data, we might need the ImplyingRules info for explainability
}

// rebuildAllowAllExplicitly : add all possible connections to the current ConnectionSet's allowed protocols
// added explicitly, without using the `AllowAll` field
func (conn *ConnectionSet) rebuildAllowAllExplicitly() {
	if !conn.AllowAll {
		return
	}
	if len(conn.AllowedProtocols) > 0 {
		return // if AllowedProtocols exist, they already include all possible connections
	}
	for _, protocol := range allProtocols {
		portSet := MakeAllPortSetWithImplyingRules(conn.CommonImplyingRules)
		conn.AddConnection(protocol, portSet)
	}
	conn.CommonImplyingRules = &ImplyingRulesType{}
}

// Union updates ConnectionSet object to be the union result with other ConnectionSet
func (conn *ConnectionSet) Union(other *ConnectionSet) {
	if conn.IsEmpty() && other.IsEmpty() && len(conn.AllowedProtocols) == 0 && len(other.AllowedProtocols) == 0 {
		// a special case when we should union implying rules
		conn.CommonImplyingRules.Union(other.CommonImplyingRules)
		return
	}
	if conn.AllowAll || other.IsEmpty() {
		return // nothing changed, shouldn't update implying rules
	}
	if other.AllowAll {
		other.rebuildAllowAllExplicitly()
	}
	for protocol := range conn.AllowedProtocols {
		if otherPorts, ok := other.AllowedProtocols[protocol]; ok {
			conn.AllowedProtocols[protocol].Union(otherPorts)
		}
	}
	for protocol := range other.AllowedProtocols {
		if _, ok := conn.AllowedProtocols[protocol]; !ok {
			conn.AllowedProtocols[protocol] = other.AllowedProtocols[protocol].Copy()
		}
	}
	conn.CommonImplyingRules = &ImplyingRulesType{} // clear common implying rules, since we have implying rules in AllowedProtocols
	conn.updateIfAllConnections()
}

// Subtract : updates current ConnectionSet object with the result of
// subtracting other ConnectionSet from current ConnectionSet
func (conn *ConnectionSet) Subtract(other *ConnectionSet) {
	if other.IsEmpty() { // nothing to subtract
		return
	}
	if conn.AllowAll {
		conn.rebuildAllowAllExplicitly()
		conn.AllowAll = false
	}
	if other.AllowAll {
		other.rebuildAllowAllExplicitly()
	}
	for protocol, ports := range conn.AllowedProtocols {
		if otherPorts, ok := other.AllowedProtocols[protocol]; ok {
			ports.subtract(otherPorts)
		}
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

// ContainedIn returns true if current ConnectionSet is contained in the input ConnectionSet object
func (conn *ConnectionSet) ContainedIn(other *ConnectionSet) bool {
	if other.AllowAll {
		return true
	}
	if conn.AllowAll {
		return false
	}
	for protocol, ports := range conn.AllowedProtocols {
		if ports.IsEmpty() {
			continue // empty port set might exist due to preserving data for explainability
		}
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
	if ports.IsUnfilled() {
		// The return below is only when 'ports' is syntactically empty;
		// In the case of a hole (semantically empty set), we do want to add it
		// in order to keep the explanation data
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
		if portsString := ports.String(); portsString != "" {
			resStrings = append(resStrings, protocolAndPortsStr(protocol, portsString))
		}
	}
	sort.Strings(resStrings)
	return strings.Join(resStrings, ",")
}

// Equal returns true if the current ConnectionSet object is equal to the input object
func (conn *ConnectionSet) Equal(other *ConnectionSet) bool {
	if conn.AllowAll != other.AllowAll {
		return false
	}
	connCanonical := conn.GetEquivalentCanonicalConnectionSet()
	otherCanonical := other.GetEquivalentCanonicalConnectionSet()
	if len(connCanonical.AllowedProtocols) != len(otherCanonical.AllowedProtocols) {
		return false
	}
	for protocol, ports := range connCanonical.AllowedProtocols {
		otherPorts, ok := otherCanonical.AllowedProtocols[protocol]
		if !ok {
			return false
		}
		if !ports.Equal(otherPorts) {
			return false
		}
	}
	return true
}

// Copy returns a new copy of ConnectionSet object
func (conn *ConnectionSet) Copy() *ConnectionSet {
	res := MakeConnectionSet(false)
	res.AllowAll = conn.AllowAll
	for protocol, portSet := range conn.AllowedProtocols {
		res.AllowedProtocols[protocol] = portSet.Copy()
	}
	res.CommonImplyingRules = conn.CommonImplyingRules.Copy()
	return res
}

// GetNamedPorts returns map from protocol to its allowed named ports (including ImplyingRules info)
func (conn *ConnectionSet) GetNamedPorts() map[v1.Protocol]NamedPortsType {
	res := make(map[v1.Protocol]NamedPortsType, 0)
	for protocol, portSet := range conn.AllowedProtocols {
		if namedPorts := portSet.GetNamedPorts(); len(namedPorts) > 0 {
			res[protocol] = namedPorts
		}
	}
	return res
}

// ReplaceNamedPortWithMatchingPortNum : replacing given namedPort with the matching given port num in the connection
// if port num is -1; just deletes the named port from the protocol's list
func (conn *ConnectionSet) ReplaceNamedPortWithMatchingPortNum(protocol v1.Protocol, namedPort string, portNum int32,
	implyingRules *ImplyingRulesType) {
	protocolPortSet := conn.AllowedProtocols[protocol]
	if portNum != NoPort {
		protocolPortSet.AddPort(intstr.FromInt32(portNum), implyingRules)
	}
	// after adding the portNum to the protocol's portSet; remove the port name
	protocolPortSet.RemovePort(intstr.FromString(namedPort))
}

// PortRangeData implements the PortRange interface
type PortRangeData struct {
	Interval AugmentedInterval
}

func (p *PortRangeData) Start() int64 {
	return p.Interval.interval.Start()
}

func (p *PortRangeData) End() int64 {
	return p.Interval.interval.End()
}

func (p *PortRangeData) String() string {
	if !p.Interval.inSet {
		return ""
	}
	if p.End() != p.Start() {
		return fmt.Sprintf("%d-%d", p.Start(), p.End())
	}
	return fmt.Sprintf("%d", p.Start())
}

func (p *PortRangeData) StringWithExplanation(protocolString string) string {
	return protocolString + ":" + p.String() + p.Interval.implyingRules.String()
}

func (p *PortRangeData) InSet() bool {
	return p.Interval.inSet
}

// ProtocolsAndPortsMap() returns a map from allowed protocol to list of allowed ports ranges.
func (conn *ConnectionSet) ProtocolsAndPortsMap(includeBlockedPorts bool) map[v1.Protocol][]PortRange {
	res := make(map[v1.Protocol][]PortRange, 0)
	for protocol, portSet := range conn.AllowedProtocols {
		res[protocol] = make([]PortRange, 0)
		// TODO: consider leave the slice of ports empty if portSet covers the full range
		for _, v := range portSet.Ports.Intervals() {
			if /*!v.isEndInterval()*/ includeBlockedPorts || v.inSet {
				res[protocol] = append(res[protocol], &PortRangeData{Interval: v})
			}
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
	connStrings := make([]string, 0, len(protocolsAndPorts))
	for protocol, ports := range protocolsAndPorts {
		if thePortsStr := portsString(ports); thePortsStr != "" {
			// thePortsStr might be empty if 'ports' does not contain 'InSet' ports
			connStrings = append(connStrings, protocolAndPortsStr(protocol, thePortsStr))
		}
	}
	sort.Strings(connStrings)
	connStr = strings.Join(connStrings, connsAndPortRangeSeparator)
	return connStr
}

// get string representation for a list of port ranges
// return a canonical form (longest in-set ranges)
func portsString(ports []PortRange) string {
	portsStr := make([]string, 0, len(ports))
	currInterval := interval.New(0, -1) // an empty interval
	for i := range ports {
		if thePortStr := ports[i].String(); thePortStr != "" {
			switch {
			case currInterval.IsEmpty():
				currInterval = interval.New(ports[i].Start(), ports[i].End())
			case currInterval.End()+1 == ports[i].Start():
				currInterval = interval.New(currInterval.Start(), ports[i].End()) // extend the interval
			default:
				portsStr = append(portsStr, currInterval.ShortString())
				currInterval = interval.New(0, -1)
			}
		} else if !currInterval.IsEmpty() { // thePortsStr will be empty if ports[i].InSet is false
			portsStr = append(portsStr, currInterval.ShortString())
			currInterval = interval.New(0, -1)
		}
	}
	if !currInterval.IsEmpty() {
		portsStr = append(portsStr, currInterval.ShortString())
	}
	return strings.Join(portsStr, connsAndPortRangeSeparator)
}

func portsStringWithExplanation(ports []PortRange, protocolString string) (string, bool) {
	portsStr := make([]string, 0, len(ports))
	noPortsExplanation := ImplyingRulesType{}
	for i := range ports {
		data := ports[i].(*PortRangeData)
		if data.InSet() {
			portsStr = append(portsStr, data.StringWithExplanation(protocolString))
		} else {
			noPortsExplanation.Union(data.Interval.implyingRules)
		}
	}
	if len(portsStr) == 0 {
		return noConnsStr + noPortsExplanation.String(), false
	}
	return strings.Join(portsStr, newLine), true
}

func protocolAndPortsStr(protocol v1.Protocol, ports string) string {
	return string(protocol) + " " + ports
}

func ExplanationFromConnProperties(allProtocolsAndPorts bool, commonImplyingRules *ImplyingRulesType,
	protocolsAndPorts map[v1.Protocol][]PortRange) string {
	if allProtocolsAndPorts || len(protocolsAndPorts) == 0 {
		connStr := noConnsStr
		if allProtocolsAndPorts {
			connStr = allConnsStr
		}
		return connStr + commonImplyingRules.String()
	}
	var connStr string
	// connStrings will contain the string of given conns protocols and ports as is
	connStrings := make([]string, 0, len(protocolsAndPorts))
	for protocol, ports := range protocolsAndPorts {
		if thePortsStr, hasPorts := portsStringWithExplanation(ports, string(protocol)); hasPorts {
			// thePortsStr might be empty if 'ports' does not contain 'InSet' ports
			connStrings = append(connStrings, thePortsStr)
		}
	}
	sort.Strings(connStrings)
	connStr = strings.Join(connStrings, connsAndPortRangeSeparator)
	return connStr
}
