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
	"strings"

	"github.com/np-guard/models/pkg/interval"
)

type ExplResultType int

const (
	NoResult ExplResultType = iota
	AllowResult
	DenyResult
)

type ImplyingXgressRulesType struct {
	Rules map[string]int
	// Result will keep the final connectivity decision which follows from the above rules
	// (allow, deny or not set)
	// It is used for specifying explainability decision per direction (Egress/Ingress)
	Result ExplResultType
}

type ImplyingRulesType struct {
	Ingress ImplyingXgressRulesType // an ordered set of ingress rules, used for explainability
	Egress  ImplyingXgressRulesType // an ordered set of egress rules, used for explainability
}

func InitImplyingXgressRules() ImplyingXgressRulesType {
	return ImplyingXgressRulesType{Rules: map[string]int{}, Result: NoResult}
}

func MakeImplyingXgressRulesWithRule(rule string) ImplyingXgressRulesType {
	res := InitImplyingXgressRules()
	res.AddXgressRule(rule)
	return res
}

func InitImplyingRules() ImplyingRulesType {
	return ImplyingRulesType{Ingress: InitImplyingXgressRules(), Egress: InitImplyingXgressRules()}
}

func MakeImplyingRulesWithRule(rule string, isIngress bool) ImplyingRulesType {
	res := InitImplyingRules()
	if isIngress {
		res.Ingress = MakeImplyingXgressRulesWithRule(rule)
	} else {
		res.Egress = MakeImplyingXgressRulesWithRule(rule)
	}
	return res
}

func (rules *ImplyingXgressRulesType) Copy() ImplyingXgressRulesType {
	if rules == nil {
		return InitImplyingXgressRules()
	}
	res := ImplyingXgressRulesType{Rules: map[string]int{}, Result: rules.Result}
	for k, v := range rules.Rules {
		res.Rules[k] = v
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
	ExplWithRulesTitle    = "due to the following policies//rules:"
	IngressDirectionTitle = "\tINGRESS DIRECTION"
	EgressDirectionTitle  = "\tEGRESS DIRECTION"
	NewLine               = "\n"
	SpaceSeparator        = " "
	ExplAllowAll          = "(Allow all)"
	SystemDefaultRule     = "the system default " + ExplAllowAll
	ExplSystemDefault     = "due to " + SystemDefaultRule
	PodToItselfRule       = "pod to itself " + ExplAllowAll
	allowResultStr        = "ALLOWED"
	denyResultStr         = "DENIED"
)

func (rules *ImplyingXgressRulesType) onlySystemDefaultRule() bool {
	if _, ok := rules.Rules[SystemDefaultRule]; ok {
		return len(rules.Rules) == 1
	}
	return false
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
	// print the rules according to their order
	formattedRules := make([]string, 0, len(rules.Rules))
	for name, order := range rules.Rules {
		formattedRules = append(formattedRules, fmt.Sprintf("\t\t%d) %s", order+1, name))
	}
	sort.Strings(formattedRules) // the rule index begins the string, like "2)"
	return rules.resultString() + NewLine + strings.Join(formattedRules, NewLine)
}

func (rules *ImplyingRulesType) OnlySystemDefaultRule() bool {
	return rules.Ingress.onlySystemDefaultRule() && rules.Egress.onlySystemDefaultRule()
}

func (rules ImplyingRulesType) String() string {
	if rules.OnlySystemDefaultRule() {
		return SpaceSeparator + SystemDefaultRule + NewLine
	}
	res := ""
	if !rules.Egress.Empty() {
		res += EgressDirectionTitle
		if rules.Egress.onlySystemDefaultRule() {
			res += SpaceSeparator + rules.Egress.resultString() + SpaceSeparator + ExplSystemDefault + NewLine
		} else {
			res += SpaceSeparator + rules.Egress.String() + NewLine
		}
	}
	if !rules.Ingress.Empty() {
		res += IngressDirectionTitle
		if rules.Ingress.onlySystemDefaultRule() {
			res += SpaceSeparator + rules.Ingress.resultString() + SpaceSeparator + ExplSystemDefault + NewLine
		} else {
			res += SpaceSeparator + rules.Ingress.String() + NewLine
		}
	}
	if res == "" {
		return NewLine
	}
	return SpaceSeparator + ExplWithRulesTitle + NewLine + res
}

func (rules *ImplyingXgressRulesType) Empty() bool {
	return len(rules.Rules) == 0
}

func (rules ImplyingRulesType) Empty(isIngress bool) bool {
	if isIngress {
		return rules.Ingress.Empty()
	}
	return rules.Egress.Empty()
}

func (rules *ImplyingXgressRulesType) AddXgressRule(ruleName string) {
	if ruleName != "" {
		if _, ok := rules.Rules[ruleName]; !ok {
			rules.Rules[ruleName] = len(rules.Rules) // a new rule should be the last
		}
	}
}

func (rules *ImplyingRulesType) AddRule(ruleName string, isIngress bool) {
	if isIngress {
		rules.Ingress.AddXgressRule(ruleName)
	} else {
		rules.Egress.AddXgressRule(ruleName)
	}
}

func (rules *ImplyingXgressRulesType) SetXgressResult(isAllowed bool) {
	if rules.Result != NoResult {
		log.Panic(errConflictingExplResult)
	}
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

func (rules *ImplyingXgressRulesType) Union(other ImplyingXgressRulesType, collectRules bool) {
	if !collectRules {
		if rules.Empty() {
			*rules = other.Copy()
		}
		return
	}

	// first, count how many rules are common in both sets
	common := 0
	for name := range other.Rules {
		if _, ok := rules.Rules[name]; ok {
			common += 1
		}
	}
	offset := len(rules.Rules) - common
	for name, order := range other.Rules {
		if _, ok := rules.Rules[name]; !ok { // for the common rules, keep their original order in the current rules
			rules.Rules[name] = order + offset // other rules should be addded after the current rules
		}
	}
	// update Result if set
	if other.Result != NoResult {
		rules.SetXgressResult(other.Result == AllowResult)
	}
}

func (rules *ImplyingXgressRulesType) mayBeUpdatedBy(other ImplyingXgressRulesType, collectRules bool) bool {
	if !collectRules {
		return rules.Empty() && !other.Empty()
	}
	for name := range other.Rules {
		if _, ok := rules.Rules[name]; !ok {
			return true
		}
	}
	return false
}

func (rules *ImplyingRulesType) Union(other ImplyingRulesType, collectRules bool) {
	rules.Ingress.Union(other.Ingress, collectRules)
	rules.Egress.Union(other.Egress, collectRules)
}

func (rules ImplyingRulesType) mayBeUpdatedBy(other ImplyingRulesType, collectRules bool) bool {
	return rules.Ingress.mayBeUpdatedBy(other.Ingress, collectRules) || rules.Egress.mayBeUpdatedBy(other.Egress, collectRules)
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

func NewAugmentedIntervalWithRule(start, end int64, inSet bool, rule string, isIngress bool) AugmentedInterval {
	return AugmentedInterval{interval: interval.New(start, end), inSet: inSet, implyingRules: MakeImplyingRulesWithRule(rule, isIngress)}
}

func NewAugmentedIntervalWithRules(start, end int64, inSet bool, rules ImplyingRulesType) AugmentedInterval {
	return AugmentedInterval{interval: interval.New(start, end), inSet: inSet, implyingRules: rules.Copy()}
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

func (c *AugmentedCanonicalSet) Intervals() []AugmentedInterval {
	return slices.Clone(c.intervalSet)
}

func (c *AugmentedCanonicalSet) NumIntervals() int {
	return len(c.intervalSet)
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

func (c *AugmentedCanonicalSet) CalculateSize() int64 {
	var res int64 = 0
	for _, r := range c.intervalSet {
		if r.inSet {
			res += r.interval.Size()
		}
	}
	return res
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
func (c *AugmentedCanonicalSet) AddAugmentedInterval(v AugmentedInterval, collectRules bool) {
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
	if v.interval.Start() > set[left].interval.Start() && (set[left].inSet != v.inSet || set[left].implyingRules.mayBeUpdatedBy(v.implyingRules, collectRules)) {
		// split set[left] into two intervals, while the implying rules of the second interval should get the new value (from v)
		new1 := AugmentedInterval{interval: interval.New(set[left].interval.Start(), v.interval.Start()-1),
			inSet: set[left].inSet, implyingRules: set[left].implyingRules.Copy()}
		var newImplyingRules ImplyingRulesType
		if set[left].inSet == v.inSet { // set[left].implyingRules.mayBeUpdatedBy(v.implyingRules, collectRules)
			newImplyingRules = set[left].implyingRules.Copy()
			newImplyingRules.Union(v.implyingRules, collectRules)
		} else {
			newImplyingRules = v.implyingRules.Copy()
		}
		new2 := AugmentedInterval{interval: interval.New(v.interval.Start(), min(set[left].interval.End(), v.interval.End())),
			inSet: v.inSet, implyingRules: newImplyingRules}
		result = append(result, new1, new2)
		left++
	}
	for ind := left; ind <= right; ind++ {
		if ind == right && v.interval.End() < set[right].interval.End() &&
			(set[right].inSet != v.inSet || set[right].implyingRules.mayBeUpdatedBy(v.implyingRules, collectRules)) {
			break // this is the corner case handled following the loop below
		}
		var newImplyingRules ImplyingRulesType
		if set[ind].inSet == v.inSet {
			// this interval is not impacted by v;
			// however, its implying rules may be updated by those of v.
			newImplyingRules = set[ind].implyingRules.Copy()
			newImplyingRules.Union(v.implyingRules, collectRules)
		} else {
			newImplyingRules = v.implyingRules.Copy()
		}
		result = append(result, AugmentedInterval{interval: set[ind].interval, inSet: v.inSet, implyingRules: newImplyingRules})
	}
	// handle the right-hand side of the intersection of v with set
	if v.interval.End() < set[right].interval.End() && (set[right].inSet != v.inSet || set[right].implyingRules.mayBeUpdatedBy(v.implyingRules, collectRules)) {
		// split set[right] into two intervals, while the implying rules of the first interval should get the new value (from v)
		if left < right || (left == right && v.interval.Start() == set[left].interval.Start()) {
			// a special case when left==right (i.e., v is included in one interval from set) was already handled
			// at the left-hand side of the intersection of v with set
			var newImplyingRules ImplyingRulesType
			if set[right].inSet == v.inSet {
				newImplyingRules = set[right].implyingRules.Copy()
				newImplyingRules.Union(v.implyingRules, collectRules)
			} else {
				newImplyingRules = v.implyingRules.Copy()
			}
			new1 := AugmentedInterval{interval: interval.New(set[right].interval.Start(), v.interval.End()),
				inSet: v.inSet, implyingRules: newImplyingRules}
			result = append(result, new1)
		}
		new2 := AugmentedInterval{interval: interval.New(v.interval.End()+1, set[right].interval.End()),
			inSet: set[right].inSet, implyingRules: set[right].implyingRules.Copy()}
		result = append(result, new2)
	}

	// copy right-end intervals not impacted by v
	result = append(result, slices.Clone(set[right+1:])...)
	c.intervalSet = result
	// TODO - optimization: unify subsequent intervals with equal inSet and implyingRules fields
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
// Note: this function is not symmetrical regarding the update of implying rules:
// it always prefers implying rules of 'c', and adds to it those of 'other' depending if collectRules == true
func (c *AugmentedCanonicalSet) Union(other *AugmentedCanonicalSet, collectRules bool) *AugmentedCanonicalSet {
	if c == other {
		return c.Copy()
	}
	// first, we add all 'out of set' intervals from both sets
	// then, we add all 'in set' intervals from both sets
	// this way we get the effect of union, while preserving all relevant implying rules
	res := NewAugmentedCanonicalSet(c.MinValue(), c.MaxValue(), false)
	for _, left := range c.intervalSet {
		if !left.inSet {
			res.AddAugmentedInterval(left, false)
		}
	}
	for _, right := range other.intervalSet {
		if !right.inSet {
			res.AddAugmentedInterval(right, false)
		}
	}
	for _, left := range c.intervalSet {
		if left.inSet {
			res.AddAugmentedInterval(left, collectRules)
		}
	}
	for _, right := range other.intervalSet {
		if right.inSet {
			res.AddAugmentedInterval(right, collectRules)
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
	otherSet.AddAugmentedInterval(NewAugmentedInterval(n, n, true), false)
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
			res.AddAugmentedInterval(left, true) // collect implying rules allowed by both sets
		}
	}
	for _, right := range other.intervalSet {
		if right.inSet {
			res.AddAugmentedInterval(right, true) // collect implying rules allowed by both sets
		}
	}
	for _, left := range c.intervalSet {
		if !left.inSet {
			res.AddAugmentedInterval(left, false)
		}
	}
	for _, right := range other.intervalSet {
		if !right.inSet {
			res.AddAugmentedInterval(right, false)
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
			res.AddAugmentedInterval(hole, false)
		}
	}
	return res
}

func (c *AugmentedCanonicalSet) ClearInSet() {
	for i := range c.intervalSet {
		c.intervalSet[i].inSet = false
	}
}

// Elements returns a slice with all the numbers contained in the set.
// USE WITH CARE. It can easily run out of memory for large sets.
func (c *AugmentedCanonicalSet) Elements() []int64 {
	// allocate memory up front, to fail early
	res := make([]int64, c.CalculateSize())
	i := 0
	for _, interval := range c.intervalSet {
		if interval.inSet {
			for v := interval.interval.Start(); v <= interval.interval.End(); v++ {
				res[i] = v
				i++
			}
		}
	}
	return res
}

func (c *AugmentedCanonicalSet) GetEquivalentCanonicalAugmentedSet() *AugmentedCanonicalSet {
	res := NewAugmentedCanonicalSet(c.MinValue(), c.MaxValue(), false)
	interv, index := c.nextIncludedInterval(0)
	for index != NoIndex {
		res.AddAugmentedInterval(NewAugmentedInterval(interv.Start(), interv.End(), true), false)
		interv, index = c.nextIncludedInterval(index + 1)
	}
	return res
}

func (c *AugmentedCanonicalSet) SetExplResult(isIngress bool) {
	for ind, v := range c.intervalSet {
		c.intervalSet[ind].implyingRules.SetResult(v.inSet, isIngress)
	}
}
