/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"fmt"
	"log"
	"slices"
	"sort"

	"github.com/np-guard/models/pkg/interval"
)

type LayerType int

const (
	DefaultLayer = iota
	BANPLayer
	NPLayer
	ANPLayer
)

type ExplResultType int

const (
	NoResult ExplResultType = iota
	AllowResult
	DenyResult
)

type ImplyingXgressRulesType struct {
	// Rules is a map from a rule kind (ANP/NP/Ingres/Route/BANP/default) to an ordered list of rules of that kind
	Rules map[string][]string
	// DominantLayer keeps the highest priority layer among the current rules;
	// used in combination with collectStyle flag (on 'NeverCollectRules' value) in updateImplyingRules
	DominantLayer LayerType
	// Result keeps the final connectivity decision which follows from the above rules
	// (allow, deny or not set)
	// It is used for specifying explainability decision per direction (Egress/Ingress)
	Result ExplResultType
}

type ImplyingRulesType struct {
	Ingress ImplyingXgressRulesType
	Egress  ImplyingXgressRulesType
}

func ruleKindToLayer(kind string) LayerType {
	switch kind {
	case "ANP":
		return ANPLayer
	case "NP":
		return NPLayer
	case "Ingress":
		return NPLayer
	case "Route":
		return NPLayer
	case "BANP":
		return BANPLayer
	case "":
		return DefaultLayer
	}
	return DefaultLayer // should not get here
}

func InitImplyingXgressRules() ImplyingXgressRulesType {
	return ImplyingXgressRulesType{Rules: map[string][]string{}, DominantLayer: DefaultLayer, Result: NoResult}
}

func MakeImplyingXgressRulesWithRule(ruleKind, rule string) ImplyingXgressRulesType {
	res := InitImplyingXgressRules()
	res.AddXgressRule(ruleKind, rule)
	return res
}

func InitImplyingRules() ImplyingRulesType {
	return ImplyingRulesType{Ingress: InitImplyingXgressRules(), Egress: InitImplyingXgressRules()}
}

func MakeImplyingRulesWithRule(ruleKind, rule string, isIngress bool) ImplyingRulesType {
	res := InitImplyingRules()
	if isIngress {
		res.Ingress = MakeImplyingXgressRulesWithRule(ruleKind, rule)
	} else {
		res.Egress = MakeImplyingXgressRulesWithRule(ruleKind, rule)
	}
	return res
}

func (rules *ImplyingXgressRulesType) Equal(other *ImplyingXgressRulesType) bool {
	return rules.String() == other.String()
}

func (rules *ImplyingRulesType) Equal(other *ImplyingRulesType) bool {
	return rules.Ingress.Equal(&other.Ingress) && rules.Egress.Equal(&other.Egress)
}

func (rules *ImplyingXgressRulesType) Copy() ImplyingXgressRulesType {
	res := ImplyingXgressRulesType{Rules: map[string][]string{}, DominantLayer: rules.DominantLayer, Result: rules.Result}
	for k, v := range rules.Rules {
		res.Rules[k] = slices.Clone(v)
	}
	return res
}

func (rules *ImplyingRulesType) Copy() ImplyingRulesType {
	res := InitImplyingRules()
	res.Ingress = rules.Ingress.Copy()
	res.Egress = rules.Egress.Copy()
	return res
}

const (
	ExplString            = "due to "
	ExplWithRulesTitle    = ExplString + "the following policies // rules:"
	IngressDirectionTitle = "\t\tINGRESS DIRECTION"
	EgressDirectionTitle  = "\t\tEGRESS DIRECTION"
	allowListTitle        = allowResultStr + listStr
	denyListTitle         = denyResultStr + listStr
	NewLine               = "\n"
	SpaceSeparator        = " "
	ExplAllowAll          = " (Allow all)"
	SystemDefaultString   = "the system default"
	SystemDefaultRule     = SystemDefaultString + ExplAllowAll
	IPDefaultString       = SystemDefaultString // currently the same as system default; change for different explanation for IP default
	IPDefaultRule         = IPDefaultString + ExplAllowAll
	ExplSystemDefault     = ExplString + SystemDefaultRule
	PodToItselfRule       = "pod to itself " + ExplAllowAll
	allowResultStr        = "ALLOWED"
	denyResultStr         = "DENIED"
	listStr               = " LIST"
)

func (rules *ImplyingXgressRulesType) onlyDefaultRule() bool {
	return len(rules.Rules) == 1 && rules.DominantLayer == DefaultLayer
}

func (rules *ImplyingXgressRulesType) getDefaultRule() string {
	return rules.Rules[""][0] // should be SystemDefaultRule
}

func (rules *ImplyingXgressRulesType) removeDefaultRule() {
	if rules.onlyDefaultRule() {
		*rules = InitImplyingXgressRules()
	}
}

func formattedExpl(expl string) string {
	return "(" + expl + ")"
}

func (rules *ImplyingXgressRulesType) resultString() string {
	switch rules.Result {
	case AllowResult:
		return formattedExpl(allowResultStr)
	case DenyResult:
		return formattedExpl(denyResultStr)
	default:
		return ""
	}
}

func (rules *ImplyingXgressRulesType) String() string {
	if rules.Empty() {
		return rules.resultString()
	}
	result := rules.resultString()
	if rules.onlyDefaultRule() {
		result += SpaceSeparator + ExplString + rules.getDefaultRule()
		return result
	}
	type rulesAndKind struct {
		ruleKind string
		ruleList string
	}
	rulesByKind := make([]rulesAndKind, 0, len(rules.Rules))
	for ruleKind, rules := range rules.Rules {
		rulesByKind = append(rulesByKind, rulesAndKind{ruleKind: ruleKind, ruleList: formatRulesOfKind(ruleKind, rules)})
	}
	// sort rule groups by layer priorities
	sort.Slice(rulesByKind, func(i, j int) bool {
		kind1 := ruleKindToLayer(rulesByKind[i].ruleKind)
		kind2 := ruleKindToLayer(rulesByKind[j].ruleKind)
		return kind1 > kind2 || (kind1 == kind2 && rulesByKind[i].ruleKind < rulesByKind[j].ruleKind)
	})

	for _, ruleAndKind := range rulesByKind {
		result += NewLine + ruleAndKind.ruleList
	}
	return result
}

func formatRulesOfKind(ruleKind string, rules []string) string {
	res := "\t\t\t"
	if len(rules) == 1 {
		return res + rules[0]
	}
	res += fmt.Sprintf("%s list:\n", ruleKind)
	for _, rule := range rules {
		res += "\t\t\t\t- " + rule + NewLine
	}
	return res
}

func (rules *ImplyingRulesType) OnlyDefaultRule() bool {
	return rules.Ingress.onlyDefaultRule() && rules.Egress.onlyDefaultRule()
}

func (rules *ImplyingRulesType) RemoveDefaultRule(isIngress bool) {
	if isIngress {
		rules.Ingress.removeDefaultRule()
	} else {
		rules.Egress.removeDefaultRule()
	}
}

func (rules ImplyingRulesType) String() string {
	if rules.OnlyDefaultRule() {
		return SpaceSeparator + ExplSystemDefault + NewLine
	}
	res := ""
	if !rules.Egress.Empty() {
		res += EgressDirectionTitle + SpaceSeparator + rules.Egress.String() + NewLine
	}
	if !rules.Ingress.Empty() {
		res += IngressDirectionTitle + SpaceSeparator + rules.Ingress.String() + NewLine
	}
	if res == "" {
		return NewLine
	}
	return SpaceSeparator + ExplWithRulesTitle + NewLine + res
}

func (rules *ImplyingXgressRulesType) Empty() bool {
	return len(rules.Rules) == 0
}

func (rules ImplyingRulesType) Empty() bool {
	return rules.Ingress.Empty() && rules.Egress.Empty()
}

func insertRuleAtIndex(rules []string, rule string, ind int) []string {
	return append(rules[:ind], append([]string{rule}, rules[ind:]...)...)
}

func (rules *ImplyingXgressRulesType) AddXgressRule(ruleKind, ruleName string) {
	if ruleName != "" {
		if _, ok := rules.Rules[ruleKind]; !ok {
			rules.Rules[ruleKind] = []string{ruleName}
		} else {
			ind := sort.SearchStrings(rules.Rules[ruleKind], ruleName)
			if ind >= len(rules.Rules[ruleKind]) || rules.Rules[ruleKind][ind] != ruleName { // avoid duplicates
				rules.Rules[ruleKind] = insertRuleAtIndex(rules.Rules[ruleKind], ruleName, ind)
			}
		}
		rules.DominantLayer = max(rules.DominantLayer, ruleKindToLayer(ruleKind))
	}
}

func (rules *ImplyingRulesType) AddRule(ruleKind, ruleName string, isIngress bool) {
	if isIngress {
		rules.Ingress.AddXgressRule(ruleKind, ruleName)
	} else {
		rules.Egress.AddXgressRule(ruleKind, ruleName)
	}
}

func (rules *ImplyingXgressRulesType) SetXgressResult(isAllowed bool) {
	if isAllowed {
		rules.Result = AllowResult
	} else {
		rules.Result = DenyResult
	}
}

func (rules *ImplyingRulesType) SetResult(isAllowed, isIngress bool) {
	if isIngress {
		rules.Ingress.SetXgressResult(isAllowed)
	} else {
		rules.Egress.SetXgressResult(isAllowed)
	}
}

// Union collects other implying rules into the current ones
func (rules *ImplyingXgressRulesType) Union(other ImplyingXgressRulesType) {
	for otherKind, otherRules := range other.Rules {
		if _, ok := rules.Rules[otherKind]; ok {
			mergedRules := rules.Rules[otherKind]
			mergedRules = append(mergedRules, otherRules...)
			sort.Strings(mergedRules)
			rules.Rules[otherKind] = slices.Compact(mergedRules)
		} else {
			rules.Rules[otherKind] = slices.Clone(otherRules)
		}
	}
	rules.DominantLayer = max(rules.DominantLayer, other.DominantLayer)
	// update Result if set
	if other.Result != NoResult {
		rules.SetXgressResult(other.Result == AllowResult)
	}
}

type CollectStyleType int

const (
	NeverCollectRules CollectStyleType = iota
	CollectSameInclusionRules
	AlwaysCollectRules
)

// Update implying rules by other (either keep, override or collect), according to the following flags:
//   - 'sameInclusion' flag if true iff there is no change in an inclusion status
//     of the updated AugmentedInterval / ConnectionSet
//     (depending if the current rules come from AugmentedInterval.implyingRules / ConnectionSet.CommonImplyingRules);
//     in case of AugmentedInterval, 'inSet' status is same, in case of ConnectionSet conn.AllowAll is same).
//   - 'collectStyle' flag specifies whether and how to collect rules (as described below).
//
// The logic of the update is as follows:
//   - if 'collectStyle' is AlwaysCollectRules (comes from Intersection of connection sets) --> collect the rules in any case
//     (Intersection of connection sets scenario, mainly for intersecion with pass connections)
//   - if 'collectStyle' is CollectSameInclusionRules and the inclusion status persists ('sameInclusion' is true) --> collect the rules
//     (Union of connection sets of multiple NPs scenario)
//   - otherwise, if the inclusion status changes ('sameInclusion' is false) --> override the rules
//   - otherwise, if the DominantLayer priortiy of the other rules is higher --> override the rules
//   - otherwise, keep the current rules.
func (rules ImplyingXgressRulesType) update(other ImplyingXgressRulesType, sameInclusion bool,
	collectStyle CollectStyleType) ImplyingXgressRulesType {
	result := rules.Copy()
	if other.Empty() {
		return result
	}
	if collectStyle == AlwaysCollectRules || (collectStyle == CollectSameInclusionRules && sameInclusion) {
		result.Union(other)
		return result
	}

	// inclusion status changes --> override
	if !sameInclusion {
		result = other.Copy()
		return result
	}
	// collectStyle == NeverCollectRules
	// inclusion status persists --> keep or override according to the priority
	if rules.Empty() || rules.DominantLayer < other.DominantLayer {
		// rules are empty or of lower priority --> override
		result = other.Copy()
	}
	return result
}

func (rules ImplyingRulesType) Update(other ImplyingRulesType, sameInclusion bool,
	collectStyle CollectStyleType) ImplyingRulesType {
	result := ImplyingRulesType{}
	result.Ingress = rules.Ingress.update(other.Ingress, sameInclusion, collectStyle)
	result.Egress = rules.Egress.update(other.Egress, sameInclusion, collectStyle)
	return result
}

// This function returns whether the current rules may be updated by the other rules.
// It follows the logic of Update() (see explanation above).
func (rules *ImplyingXgressRulesType) mayBeUpdatedBy(other ImplyingXgressRulesType, sameInclusion bool,
	collectStyle CollectStyleType) bool {
	if collectStyle == AlwaysCollectRules || (collectStyle == CollectSameInclusionRules && sameInclusion) {
		// return true iff Union would change anything
		for otherKind, otherRules := range other.Rules {
			if _, ok := rules.Rules[otherKind]; !ok {
				return true
			}
			for _, otherRule := range otherRules {
				ind := sort.SearchStrings(rules.Rules[otherKind], otherRule)
				if ind >= len(rules.Rules[otherKind]) || rules.Rules[otherKind][ind] != otherRule {
					return true
				}
			}
		}
		return false
	}
	return (!sameInclusion || rules.Empty() && !other.Empty()) || rules.DominantLayer < other.DominantLayer
}

func (rules ImplyingRulesType) mayBeUpdatedBy(other ImplyingRulesType, sameInclusion bool,
	collectStyle CollectStyleType) bool {
	return rules.Ingress.mayBeUpdatedBy(other.Ingress, sameInclusion, collectStyle) ||
		rules.Egress.mayBeUpdatedBy(other.Egress, sameInclusion, collectStyle)
}

const (
	NoIndex = -1
)

type AugmentedInterval struct {
	interval      interval.Interval
	inSet         bool
	implyingRules ImplyingRulesType
}

func NewAugmentedInterval(start, end int64, inSet bool) AugmentedInterval {
	return AugmentedInterval{interval: interval.New(start, end), inSet: inSet, implyingRules: InitImplyingRules()}
}

func NewAugmentedIntervalWithRule(start, end int64, inSet bool, ruleKind, rule string, isIngress bool) AugmentedInterval {
	return AugmentedInterval{interval: interval.New(start, end), inSet: inSet,
		implyingRules: MakeImplyingRulesWithRule(ruleKind, rule, isIngress)}
}

func NewAugmentedIntervalWithRules(start, end int64, inSet bool, rules ImplyingRulesType) AugmentedInterval {
	return AugmentedInterval{interval: interval.New(start, end), inSet: inSet, implyingRules: rules.Copy()}
}

func (augInt AugmentedInterval) Equal(other AugmentedInterval) bool {
	return augInt.inSet == other.inSet && augInt.interval.Equal(other.interval) && augInt.implyingRules.Equal(&other.implyingRules)
}

// AugmentedCanonicalSet is a set of int64 integers, implemented using an ordered slice of non-overlapping, non-touching intervals.
// The intervals should include both included intervals and holes;
// i.e., start of every interval is the end of a previous interval incremented by 1.
// An AugmentedCanonicalSet is created with an interval/hole covering the whole range for this kind of set.
// The assumption is that further operations on a set will never extend this initial range,
// i.e., the MinValue() and MaxValue() functions will always return the same results.
type AugmentedCanonicalSet struct {
	intervalSet []AugmentedInterval
}

func NewAugmentedCanonicalSet(minValue, maxValue int64, isAll bool) *AugmentedCanonicalSet {
	return &AugmentedCanonicalSet{
		intervalSet: []AugmentedInterval{
			NewAugmentedInterval(minValue, maxValue, isAll), // the full range interval (isAll==true) or 'hole' (isAll==false)
		},
	}
}

func NewAugmentedCanonicalSetWithRules(minValue, maxValue int64, isAll bool, rules ImplyingRulesType) *AugmentedCanonicalSet {
	return &AugmentedCanonicalSet{
		intervalSet: []AugmentedInterval{
			NewAugmentedIntervalWithRules(minValue, maxValue, isAll, rules), // the full range interval (isAll==true) or 'hole' (isAll==false)
		},
	}
}

func (c *AugmentedCanonicalSet) RemoveDefaultRule(isIngress bool) {
	for ind := range c.intervalSet {
		c.intervalSet[ind].implyingRules.RemoveDefaultRule(isIngress)
	}
}

func (c *AugmentedCanonicalSet) Intervals() []AugmentedInterval {
	return slices.Clone(c.intervalSet)
}

const (
	errMinFromEmptySet       = "cannot take min from empty interval set"
	errOutOfRangeInterval    = "cannot add interval which is out of scope of AugmentedCanonicalSet"
	errConflictingExplResult = "cannot override explanation result that has been already set"
)

func (c *AugmentedCanonicalSet) MinValue() int64 {
	if len(c.intervalSet) == 0 {
		log.Panic(errMinFromEmptySet)
	}
	return c.intervalSet[0].interval.Start()
}

func (c *AugmentedCanonicalSet) MaxValue() int64 {
	size := len(c.intervalSet)
	if size == 0 {
		log.Panic(errMinFromEmptySet)
	}
	return c.intervalSet[size-1].interval.End()
}

func (c *AugmentedCanonicalSet) Min() int64 {
	if len(c.intervalSet) == 0 {
		log.Panic(errMinFromEmptySet)
	}
	for _, interval := range c.intervalSet {
		if interval.inSet {
			return interval.interval.Start()
		}
	}
	log.Panic(errMinFromEmptySet)
	return 0 // making linter happy
}

// IsEmpty returns true if the AugmentedCanonicalSet is semantically empty (i.e., no 'inSet' intervals, but may possibly include holes)
func (c *AugmentedCanonicalSet) IsEmpty() bool {
	for _, interval := range c.intervalSet {
		if interval.inSet {
			return false
		}
	}
	return true
}

// Unfilled returns true if the AugmentedCanonicalSet is syntactically empty (i.e., none of intervals or holes in the interval set)
func (c *AugmentedCanonicalSet) IsUnfilled() bool {
	return len(c.intervalSet) == 0
}

// func (c *AugmentedCanonicalSet) isConsistent() bool {
// 	lastInd := len(c.intervalSet) - 1
// 	if lastInd < 0 {
// 		return true // the set is empty
// 	}
// 	lastInterval := c.intervalSet[lastInd]
// 	if lastInterval.inSet || lastInterval.interval.Start() < 0 || lastInterval.interval.End() != MaxValue {
// 		return false
// 	}
// 	return true
// }

// nextIncludedInterval finds an interval included in set (not hole), starting from fromInd.
// if there are a few continuous in set intervals, it will return the union of all of them.
// it returns the found (potentially extended) interval, and the biggest index contributing to the result
func (c *AugmentedCanonicalSet) nextIncludedInterval(fromInd int) (res interval.Interval, index int) {
	start := fromInd
	for start < len(c.intervalSet) && !c.intervalSet[start].inSet {
		start++
	}
	if start >= len(c.intervalSet) {
		return interval.New(0, -1), NoIndex
	}
	end := start
	for end < len(c.intervalSet) && c.intervalSet[end].inSet {
		end++
	}
	return interval.New(c.intervalSet[start].interval.Start(), c.intervalSet[end-1].interval.End()), end - 1
}

// Equal returns true if the AugmentedCanonicalSet semantically equals the other AugmentedCanonicalSet;
// only numeric intervals are compared; the implying rules are not compared.
func (c *AugmentedCanonicalSet) Equal(other *AugmentedCanonicalSet) bool {
	if c == other {
		return true
	}
	currThisInd := 0
	currOtherInd := 0

	for currThisInd != NoIndex {
		thisInterval, thisInd := c.nextIncludedInterval(currThisInd)
		otherInterval, otherInd := other.nextIncludedInterval(currOtherInd)
		if (thisInd == NoIndex) != (otherInd == NoIndex) {
			return false
		}
		if thisInd == NoIndex {
			break
		}
		if !(thisInterval.Equal(otherInterval)) {
			return false
		}
		currThisInd = thisInd + 1
		currOtherInd = otherInd + 1
	}
	return true
}

// AddAugmentedInterval adds a new interval/hole  to the set,
// and updates the implying rules accordingly
//
//gocyclo:ignore
func (c *AugmentedCanonicalSet) AddAugmentedInterval(v AugmentedInterval, collectStyle CollectStyleType) {
	if v.interval.Start() < c.MinValue() || v.interval.End() > c.MaxValue() {
		log.Panic(errOutOfRangeInterval)
	}
	if v.interval.IsEmpty() {
		return
	}
	set := c.intervalSet
	left := sort.Search(len(set), func(i int) bool {
		return set[i].interval.End() >= v.interval.Start()
	})
	right := sort.Search(len(set), func(j int) bool {
		return set[j].interval.End() >= v.interval.End()
	})
	var result []AugmentedInterval
	// copy left-end intervals not impacted by v
	result = append(result, slices.Clone(set[0:left])...)

	// handle the left-hand side of the intersection of v with set
	sameInclusion := set[left].inSet == v.inSet
	if v.interval.Start() > set[left].interval.Start() &&
		(!sameInclusion || set[left].implyingRules.mayBeUpdatedBy(v.implyingRules, sameInclusion, collectStyle)) {
		// split set[left] into two intervals, while the implying rules of the second interval should get the new value (from v)
		new1 := AugmentedInterval{interval: interval.New(set[left].interval.Start(), v.interval.Start()-1),
			inSet: set[left].inSet, implyingRules: set[left].implyingRules.Copy()}
		new2 := AugmentedInterval{interval: interval.New(v.interval.Start(), min(set[left].interval.End(), v.interval.End())),
			inSet: v.inSet, implyingRules: set[left].implyingRules.Update(v.implyingRules, sameInclusion, collectStyle)}
		result = append(result, new1, new2)
		left++
	}
	for ind := left; ind <= right; ind++ {
		sameInclusion := set[ind].inSet == v.inSet
		if ind == right && v.interval.End() < set[right].interval.End() &&
			(!sameInclusion || set[right].implyingRules.mayBeUpdatedBy(v.implyingRules, sameInclusion, collectStyle)) {
			break // this is the corner case handled following the loop below
		}
		result = append(result, AugmentedInterval{interval: set[ind].interval, inSet: v.inSet,
			implyingRules: set[ind].implyingRules.Update(v.implyingRules, sameInclusion, collectStyle)})
	}
	// handle the right-hand side of the intersection of v with set
	sameInclusion = set[right].inSet == v.inSet
	if v.interval.End() < set[right].interval.End() &&
		(!sameInclusion || set[right].implyingRules.mayBeUpdatedBy(v.implyingRules, sameInclusion, collectStyle)) {
		// split set[right] into two intervals, while the implying rules of the first interval should get the new value (from v)
		if left < right || (left == right && v.interval.Start() == set[left].interval.Start()) {
			// a special case when left==right (i.e., v is included in one interval from set) was already handled
			// at the left-hand side of the intersection of v with set
			new1 := AugmentedInterval{interval: interval.New(set[right].interval.Start(), v.interval.End()), inSet: v.inSet,
				implyingRules: set[right].implyingRules.Update(v.implyingRules, sameInclusion, collectStyle)}
			result = append(result, new1)
		}
		new2 := AugmentedInterval{interval: interval.New(v.interval.End()+1, set[right].interval.End()),
			inSet: set[right].inSet, implyingRules: set[right].implyingRules.Copy()}
		result = append(result, new2)
	}

	// copy right-end intervals not impacted by v
	result = append(result, slices.Clone(set[right+1:])...)
	c.intervalSet = result
}

// String returns a string representation of the current CanonicalSet object
func (c *AugmentedCanonicalSet) String() string {
	if c.IsEmpty() {
		return ""
	}
	res := ""
	canonical := c.GetEquivalentCanonicalAugmentedSet()
	for _, interval := range canonical.intervalSet {
		if interval.inSet {
			res += interval.interval.ShortString() + ","
		}
	}
	return res[:len(res)-1]
}

// Union returns the union of the two sets
func (c *AugmentedCanonicalSet) Union(other *AugmentedCanonicalSet, collectSameInclusionRules bool) *AugmentedCanonicalSet {
	if c == other {
		return c.Copy()
	}
	collectStyle := NeverCollectRules
	if collectSameInclusionRules {
		collectStyle = CollectSameInclusionRules
	}
	// first, we add all 'out of set' intervals from both sets
	// then, we add all 'in set' intervals from both sets
	// this way we get the effect of union, while preserving all relevant implying rules
	res := NewAugmentedCanonicalSet(c.MinValue(), c.MaxValue(), false)
	for _, left := range c.intervalSet {
		if !left.inSet {
			res.AddAugmentedInterval(left, collectStyle)
		}
	}
	for _, right := range other.intervalSet {
		if !right.inSet {
			res.AddAugmentedInterval(right, collectStyle)
		}
	}
	for _, left := range c.intervalSet {
		if left.inSet {
			res.AddAugmentedInterval(left, collectStyle)
		}
	}
	for _, right := range other.intervalSet {
		if right.inSet {
			res.AddAugmentedInterval(right, collectStyle)
		}
	}
	return res
}

// Copy returns a new copy of the CanonicalSet object
func (c *AugmentedCanonicalSet) Copy() *AugmentedCanonicalSet {
	return &AugmentedCanonicalSet{intervalSet: slices.Clone(c.intervalSet)}
}

func (c *AugmentedCanonicalSet) Contains(n int64) bool {
	otherSet := NewAugmentedCanonicalSet(c.MinValue(), c.MaxValue(), false)
	otherSet.AddAugmentedInterval(NewAugmentedInterval(n, n, true), NeverCollectRules)
	return otherSet.ContainedIn(c)
}

// ContainedIn returns true of the current AugmentedCanonicalSet is contained in the other AugmentedCanonicalSet
func (c *AugmentedCanonicalSet) ContainedIn(other *AugmentedCanonicalSet) bool {
	if c == other {
		return true
	}
	currThisInd := 0
	currOtherInd := 0
	for currThisInd != NoIndex {
		thisInterval, thisInd := c.nextIncludedInterval(currThisInd)
		otherInterval, otherInd := other.nextIncludedInterval(currOtherInd)
		if thisInd == NoIndex {
			return true // end of this interval set
		}
		if otherInd == NoIndex {
			return false // end of other interval set, but still have uncovered interval in this set
		}
		if thisInterval.IsSubset(otherInterval) {
			// this interval is included in other; move to next intervals
			currThisInd = thisInd + 1
			currOtherInd = otherInd + 1
			continue
		}
		if thisInterval.Overlap(otherInterval) {
			// only part of this interval is contained
			return false
		}
		if thisInterval.End() < otherInterval.Start() {
			// this interval is not contained here
			return false
		}
		// otherInterval.End() < thisInterval.Start()
		// increment currOtherInd
		currOtherInd = otherInd + 1
	}
	return true
}

// Intersect returns the intersection of the current set with the input set
func (c *AugmentedCanonicalSet) Intersect(other *AugmentedCanonicalSet) *AugmentedCanonicalSet {
	if c == other {
		return c.Copy()
	}
	// first, we add all 'in set' intervals from both sets
	// then, we add all 'out of set' intervals from both sets
	// this way we get the effect of intersection, while preserving all relevant implying rules
	res := NewAugmentedCanonicalSet(c.MinValue(), c.MaxValue(), false)
	for _, left := range c.intervalSet {
		if left.inSet {
			res.AddAugmentedInterval(left, AlwaysCollectRules) // collect implying rules allowed by both sets
		}
	}
	for _, right := range other.intervalSet {
		if right.inSet {
			res.AddAugmentedInterval(right, AlwaysCollectRules) // collect implying rules allowed by both sets
		}
	}
	for _, left := range c.intervalSet {
		if !left.inSet {
			res.AddAugmentedInterval(left, AlwaysCollectRules) // collect implying rules denied by both sets
		}
	}
	for _, right := range other.intervalSet {
		if !right.inSet {
			res.AddAugmentedInterval(right, AlwaysCollectRules) // collect implying rules denied by both sets
		}
	}
	return res
}

// Overlap returns true if current AugmentedCanonicalSet overlaps with input AugmentedCanonicalSet
func (c *AugmentedCanonicalSet) Overlap(other *AugmentedCanonicalSet) bool {
	if c == other {
		return !c.IsEmpty()
	}
	currThisInd := 0
	currOtherInd := 0
	for currThisInd != NoIndex {
		thisInterval, thisInd := c.nextIncludedInterval(currThisInd)
		otherInterval, otherInd := other.nextIncludedInterval(currOtherInd)
		if thisInd == NoIndex || otherInd == NoIndex {
			return false // did not find overlapping interval
		}
		if thisInterval.Overlap(otherInterval) {
			return true
		}
		if thisInterval.End() < otherInterval.Start() {
			// increment currThisInd
			currThisInd = thisInd + 1
		} else { // otherInterval.End() < thisInterval.Start()
			// increment currOtherInd
			currOtherInd = otherInd + 1
		}
	}
	return false
}

// Subtract returns the subtraction result of other AugmentedCanonicalSet
func (c *AugmentedCanonicalSet) Subtract(other *AugmentedCanonicalSet) *AugmentedCanonicalSet {
	if c == other {
		return NewAugmentedCanonicalSet(c.MinValue(), c.MaxValue(), false)
	}
	res := c.Copy()
	for _, interval := range other.intervalSet {
		if interval.inSet {
			hole := interval
			hole.inSet = false
			res.AddAugmentedInterval(hole, NeverCollectRules)
		}
	}
	return res
}

func (c *AugmentedCanonicalSet) GetEquivalentCanonicalAugmentedSet() *AugmentedCanonicalSet {
	res := NewAugmentedCanonicalSet(c.MinValue(), c.MaxValue(), false)
	interv, index := c.nextIncludedInterval(0)
	for index != NoIndex {
		res.AddAugmentedInterval(NewAugmentedInterval(interv.Start(), interv.End(), true), NeverCollectRules)
		interv, index = c.nextIncludedInterval(index + 1)
	}
	return res
}

func (c *AugmentedCanonicalSet) SetExplResult(isIngress bool) {
	for ind, v := range c.intervalSet {
		c.intervalSet[ind].implyingRules.SetResult(v.inSet, isIngress)
	}
}
