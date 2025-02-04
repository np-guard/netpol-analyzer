/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"fmt"
	"log"
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
	CommonImplyingRules ImplyingRulesType        // used for explainability, when AllowedProtocols is empty (i.e., all allowed or all denied)
}

func ExplNoMatchOfNamedPortsToDst(ruleName string) string {
	return fmt.Sprintf("%s (named ports of the rule have no match in the configuration of the dst peer)", ruleName)
}

func ExplNotReferencedPorts(ruleName string) string {
	return fmt.Sprintf("%s (ports not referenced)", ruleName)
}

func ExplNotReferencedProtocols(ruleName string) string {
	return fmt.Sprintf("%s (protocols not referenced)", ruleName)
}

var allProtocols = []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP, v1.ProtocolSCTP}

// MakeConnectionSet returns a pointer to ConnectionSet object with all connections or no connections
func MakeConnectionSet(all bool) *ConnectionSet {
	if all {
		return &ConnectionSet{AllowAll: true, AllowedProtocols: map[v1.Protocol]*PortSet{}, CommonImplyingRules: InitImplyingRules()}
	}
	return &ConnectionSet{AllowedProtocols: map[v1.Protocol]*PortSet{}, CommonImplyingRules: InitImplyingRules()}
}

func MakeConnectionSetWithRule(all bool, rule string, layer LayerType, isIngress bool) *ConnectionSet {
	return &ConnectionSet{AllowAll: all, AllowedProtocols: map[v1.Protocol]*PortSet{},
		CommonImplyingRules: MakeImplyingRulesWithRule(rule, layer, isIngress)}
}

// Add common implying rule, i.e., a rule that is relevant for the whole ConnectionSet
func (conn *ConnectionSet) AddCommonImplyingRule(implyingRule string, layer LayerType, isIngress bool) {
	conn.CommonImplyingRules.AddRule(implyingRule, layer, isIngress)
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

func (conn *ConnectionSet) RemoveDefaultRule(isIngress bool) {
	conn.CommonImplyingRules.RemoveDefaultRule(isIngress)
	for _, ports := range conn.AllowedProtocols {
		ports.RemoveDefaultRule(isIngress)
	}
}

// GetAllTCPConnections returns a pointer to ConnectionSet object with all TCP protocol connections
func GetAllTCPConnections() *ConnectionSet {
	tcpConn := MakeConnectionSet(false)
	tcpConn.AddConnection(v1.ProtocolTCP, MakePortSet(true))
	return tcpConn
}

// Intersection updates ConnectionSet object to be the intersection result with other ConnectionSet
// the implying rules are symmetrically updated by both conn and other,
// i.e., conn does not have a precedence over other
func (conn *ConnectionSet) Intersection(other *ConnectionSet) {
	if len(conn.AllowedProtocols) == 0 && len(other.AllowedProtocols) == 0 {
		// each one of conn and other is either AllowAll or Empty
		if other.IsEmpty() {
			conn.AllowAll = false
			conn.AllowedProtocols = map[v1.Protocol]*PortSet{}
		}
		// union common implying rules - a symmetrical update
		conn.CommonImplyingRules = conn.CommonImplyingRules.Update(other.CommonImplyingRules, true, AlwaysCollectRules)
		return
	}
	// prepare conn and other for the intersection - we need to seep implying rules info into all protocols/ports
	conn.rebuildExplicitly()
	other.rebuildExplicitly()
	conn.AllowAll = false
	for protocol := range conn.AllowedProtocols {
		otherPorts, ok := other.AllowedProtocols[protocol]
		if !ok {
			log.Panic("We should not get here")
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

func (conn *ConnectionSet) SetExplResult(isIngress bool) {
	if len(conn.AllowedProtocols) == 0 {
		// no AllowedProtocols --> compute result according to AllowAll
		conn.CommonImplyingRules.SetResult(conn.AllowAll, isIngress)
		return
	}
	// compute result for every range in AllowedProtocols
	for _, ports := range conn.AllowedProtocols {
		ports.Ports.SetExplResult(isIngress)
	}
}

// rebuildExplicitly : represent All/No connections explicitly (All connections if AllowAll==true, No connections otherwise),
// by building AllowedProtocols and adding the whole range intervals/holes (depending on AllowAll field)
func (conn *ConnectionSet) rebuildExplicitly() {
	// we don't assume that conn.AllowedProtocols contains only protocols from allProtocols var.
	// in case of exposure analysis with named ports, a protocol with an empty name may exist.
	// if len(conn.AllowedProtocols) == len(allProtocols) {
	// 	return // if all protocols exist, nothing to add
	// }
	var portSet *PortSet
	if conn.AllowAll {
		portSet = MakeAllPortSetWithImplyingRules(conn.CommonImplyingRules)
	} else {
		portSet = MakeEmptyPortSetWithImplyingRules(conn.CommonImplyingRules)
	}
	for _, protocol := range allProtocols {
		if _, ok := conn.AllowedProtocols[protocol]; !ok {
			conn.AddConnection(protocol, portSet)
		}
	}
	conn.CommonImplyingRules = InitImplyingRules()
}

// Union updates ConnectionSet object to be the union result with other ConnectionSet
func (conn *ConnectionSet) Union(other *ConnectionSet, collectSameInclusionRules bool) {
	collectStyle := NeverCollectRules
	if collectSameInclusionRules {
		collectStyle = CollectSameInclusionRules
	}
	if (conn.IsEmpty() || conn.AllowAll) && (other.IsEmpty() || other.AllowAll) &&
		len(conn.AllowedProtocols) == 0 && len(other.AllowedProtocols) == 0 {
		conn.CommonImplyingRules = conn.CommonImplyingRules.Update(other.CommonImplyingRules,
			conn.AllowAll == other.AllowAll, collectStyle)
		conn.AllowAll = conn.AllowAll || other.AllowAll
		return
	}
	if other.IsEmpty() {
		return // neither connections nor implying rules can be updated
	}
	conn.rebuildExplicitly()
	other.rebuildExplicitly()
	for protocol := range conn.AllowedProtocols {
		if otherPorts, ok := other.AllowedProtocols[protocol]; ok {
			conn.AllowedProtocols[protocol].Union(otherPorts, collectSameInclusionRules)
		}
	}
	// we don't assume that conn and other contain only protocols from allProtocols var.
	// in case of exposure analysis with named ports, a protocol with an empty name may exist.
	// in order to not assume empty name, we pick here all protocols from other, not appearing in conn
	for protocol, ports := range other.AllowedProtocols {
		if _, ok := conn.AllowedProtocols[protocol]; !ok {
			conn.AddConnection(protocol, ports)
		}
	}

	conn.CommonImplyingRules = InitImplyingRules() // clear common implying rules, since we have implying rules in AllowedProtocols
	conn.updateIfAllConnections()
}

// Subtract : updates current ConnectionSet object with the result of
// subtracting other ConnectionSet from current ConnectionSet
// the implying rules are updated by both conn and other
func (conn *ConnectionSet) Subtract(other *ConnectionSet) {
	if /*conn.IsEmpty() ||*/ other.IsEmpty() { // nothing to subtract
		return
	}
	if other.AllowAll && len(other.AllowedProtocols) == 0 {
		// a special case when we should override the current common implying rules by others'
		// because conn.AllowAll (aka the inclusion status) changes
		conn.CommonImplyingRules = conn.CommonImplyingRules.Update(other.CommonImplyingRules, false, NeverCollectRules)
		conn.AllowAll = false
		conn.AllowedProtocols = map[v1.Protocol]*PortSet{}
		return
	}
	conn.rebuildExplicitly()
	conn.AllowAll = false
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
		connPorts.Union(ports, true)
	} else {
		conn.AllowedProtocols[protocol] = ports.Copy()
	}
}

// String returns a string representation of the ConnectionSet object
func (conn *ConnectionSet) String() string {
	if conn.AllowAll {
		return AllConnsStr
	} else if conn.IsEmpty() {
		return NoConnsStr
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
	implyingRules ImplyingRulesType) {
	protocolPortSet := conn.AllowedProtocols[protocol]
	if portNum != NoPort {
		protocolPortSet.ReplaceNamedPort(namedPort, intstr.FromInt32(portNum), implyingRules)
	} else {
		// this should not happen
		protocolPortSet.RemovePort(intstr.FromString(namedPort))
	}
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

func (p *PortRangeData) isWholeRange() bool {
	return p.Start() == MinPort && p.End() == MaxPort
}

func (p PortRangeData) Equal(other PortRangeData) bool {
	return p.Interval.Equal(other.Interval)
}

func (p *PortRangeData) String() string {
	if p.isWholeRange() {
		return allPortsStr
	}
	if p.End() != p.Start() {
		return fmt.Sprintf("%d-%d", p.Start(), p.End())
	}
	return fmt.Sprintf("%d", p.Start())
}

func explOfInSetProtocolPortsAndRules(inSet bool, protocolString, portsString, rulesString string) string {
	resultStr := allowResultStr
	if !inSet {
		resultStr = denyResultStr
	}
	return resultStr + SpaceSeparator + protocolString + ":" + "[" + portsString + "]" + rulesString
}

func (p *PortRangeData) StringWithExplanation(protocolString string) string {
	return explOfInSetProtocolPortsAndRules(p.InSet(), protocolString, p.String(), p.Interval.implyingRules.String())
}

func (p *PortRangeData) InSet() bool {
	return p.Interval.inSet
}

// ProtocolsAndPortsMap() returns a map from allowed protocol to list of allowed ports ranges.
func (conn *ConnectionSet) ProtocolsAndPortsMap(includeDeniedPorts bool) map[v1.Protocol][]PortRange {
	res := make(map[v1.Protocol][]PortRange, 0)
	for protocol, portSet := range conn.AllowedProtocols {
		res[protocol] = make([]PortRange, 0)
		// TODO: consider leave the slice of ports empty if portSet covers the full range
		for _, v := range portSet.Ports.Intervals() {
			if includeDeniedPorts || v.inSet {
				res[protocol] = append(res[protocol], &PortRangeData{Interval: v})
			}
		}
	}
	return res
}

// IsAllConnections returns true if all ports are allowed for all protocols
func (conn *ConnectionSet) IsAllConnections() bool {
	return conn.AllowAll
}

const (
	connsAndPortRangeSeparator = ","
	AllConnsStr                = "All Connections"
	NoConnsStr                 = "No Connections"
	allPortsStr                = "ALL PORTS"
)

func ConnStrFromConnProperties(allProtocolsAndPorts bool, protocolsAndPorts map[v1.Protocol][]PortRange) string {
	if allProtocolsAndPorts {
		return AllConnsStr
	}
	if len(protocolsAndPorts) == 0 {
		return NoConnsStr
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
		if ports[i].(*PortRangeData).InSet() {
			if currInterval.IsEmpty() {
				currInterval = interval.New(ports[i].Start(), ports[i].End())
			} else { // the intervals are consequent, i.e., currInterval.End()+1 == ports[i].Start()
				currInterval = interval.New(currInterval.Start(), ports[i].End()) // extend the interval
			}
		} else if !currInterval.IsEmpty() {
			portsStr = append(portsStr, currInterval.ShortString())
			currInterval = interval.New(0, -1)
		}
	}
	if !currInterval.IsEmpty() {
		portsStr = append(portsStr, currInterval.ShortString())
	}
	return strings.Join(portsStr, connsAndPortRangeSeparator)
}

type InSetAndRulesStr struct {
	inSet       bool
	rulesString string
}

func portsStringWithExplanation(ports []PortRange, protocolString string) []string {
	// for compact explanation: collect together ranges with the same 'inSet' and impying rules
	portRangeClasses := map[InSetAndRulesStr]*interval.CanonicalSet{}
	for i := range ports {
		portRangeData := ports[i].(*PortRangeData)
		thisInSetAndRulesStr := InSetAndRulesStr{portRangeData.Interval.inSet, portRangeData.Interval.implyingRules.String()}
		_, ok := portRangeClasses[thisInSetAndRulesStr]
		if !ok {
			portRangeClasses[thisInSetAndRulesStr] = interval.NewCanonicalSet()
		}
		portRangeClasses[thisInSetAndRulesStr].AddInterval(portRangeData.Interval.interval)
	}
	portsStr := make([]string, len(portRangeClasses))
	ind := 0
	for inSetAndRulesStr, intervals := range portRangeClasses {
		portsStr[ind] = explOfInSetProtocolPortsAndRules(inSetAndRulesStr.inSet, protocolString,
			intervals.String(), inSetAndRulesStr.rulesString)
		ind++
	}
	sort.Strings(portsStr)
	return portsStr
}

func protocolAndPortsStr(protocol v1.Protocol, ports string) string {
	return string(protocol) + SpaceSeparator + ports
}

func isWholeRange(ports []PortRange) bool {
	return len(ports) == 1 && ports[0].(*PortRangeData).isWholeRange()
}

func ExplanationFromConnProperties(allProtocolsAndPorts bool, commonImplyingRules ImplyingRulesType,
	protocolsAndPorts map[v1.Protocol][]PortRange) string {
	if len(protocolsAndPorts) == 0 {
		connStr := NoConnsStr
		if allProtocolsAndPorts {
			connStr = AllConnsStr
		}
		return connStr + commonImplyingRules.String()
	}
	var connStr string
	// connStrings will contain the string of given conns protocols and ports as is
	connStrings := make([]string, 0, len(protocolsAndPorts))
	// for compact explanation: pick all protocols containing the whole port range
	wholeCommonRange := PortRangeData{}
	wholeRangeProtocols := make([]string, 0, len(protocolsAndPorts))
	for protocol, ports := range protocolsAndPorts {
		if isWholeRange(ports) {
			if len(wholeRangeProtocols) == 0 {
				wholeCommonRange = *ports[0].(*PortRangeData)
				wholeRangeProtocols = append(wholeRangeProtocols, string(protocol))
				continue
			} else if ports[0].(*PortRangeData).Equal(wholeCommonRange) {
				wholeRangeProtocols = append(wholeRangeProtocols, string(protocol))
				continue
			}
		}
		connStrings = append(connStrings, portsStringWithExplanation(ports, string(protocol))...)
	}
	if len(wholeRangeProtocols) > 0 {
		sort.Strings(wholeRangeProtocols)
		connStrings = append(connStrings, wholeCommonRange.StringWithExplanation("{"+strings.Join(wholeRangeProtocols, ",")+"}"))
	}
	sort.Strings(connStrings)
	connStr = strings.Join(connStrings, NewLine)
	return connStr
}
