/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"log"
	"math"
	"slices"
	"sort"

	"github.com/np-guard/models/pkg/interval"
)

type ImplyingRulesType map[string]bool // an ordered set of rules; used for explainability

func MakeImplyingRulesWithRule(rule string) *ImplyingRulesType {
	res := ImplyingRulesType{}
	res.AddRule(rule)
	return &res
}

func (rules *ImplyingRulesType) Copy() *ImplyingRulesType {
	if rules == nil {
		return nil
	}
	res := ImplyingRulesType{}
	for k, v := range *rules {
		res[k] = v
	}
	return &res
}

func (rules ImplyingRulesType) Empty() bool {
	return len(rules) == 0
}

func (rules *ImplyingRulesType) AddRule(ruleName string) {
	if ruleName != "" {
		(*rules)[ruleName] = true
	}
}

func (rules *ImplyingRulesType) Union(other *ImplyingRulesType) {
	if other == nil {
		return
	}
	for k, v := range *other {
		(*rules)[k] = v // v should be always true
	}
}

const (
	MinValue = 0
	MaxValue = math.MaxInt64
	NoIndex  = -1
)

type AugmentedInterval struct {
	interval      interval.Interval
	inSet         bool
	implyingRules *ImplyingRulesType
}

func (augInt *AugmentedInterval) isEndInterval() bool {
	return !augInt.inSet && augInt.interval.End() == MaxValue
}

func NewAugmentedInterval(start, end int64, inSet bool) AugmentedInterval {
	return AugmentedInterval{interval: interval.New(start, end), inSet: inSet, implyingRules: &ImplyingRulesType{}}
}

func NewAugmentedIntervalWithRule(start, end int64, inSet bool, rule string) AugmentedInterval {
	return AugmentedInterval{interval: interval.New(start, end), inSet: inSet, implyingRules: MakeImplyingRulesWithRule(rule)}
}

func NewAugmentedIntervalWithRules(start, end int64, inSet bool, rules *ImplyingRulesType) AugmentedInterval {
	return AugmentedInterval{interval: interval.New(start, end), inSet: inSet, implyingRules: rules.Copy()}
}

// AugmentedCanonicalSet is a set of int64 integers, implemented using an ordered slice of non-overlapping, non-touching interval.
// The intervals should include both included intervals and holes;
// i.e., start of every interval is the end of a previous interval incremented by 1.
// The last interval should always end with MaxValue and should have inSet being false (thus representing a hole till the end of the range)
type AugmentedCanonicalSet struct {
	intervalSet []AugmentedInterval
}

func NewAugmentedCanonicalSet() *AugmentedCanonicalSet {
	return &AugmentedCanonicalSet{
		intervalSet: []AugmentedInterval{
			NewAugmentedInterval(MinValue, MaxValue, false), // the full range 'hole'
		},
	}
}

func (c *AugmentedCanonicalSet) Intervals() []AugmentedInterval {
	return slices.Clone(c.intervalSet)
}

func (c *AugmentedCanonicalSet) NumIntervals() int {
	return len(c.intervalSet)
}

func (c *AugmentedCanonicalSet) Min() int64 {
	if len(c.intervalSet) == 0 {
		log.Panic("cannot take min from empty interval set")
	}
	for _, interval := range c.intervalSet {
		if interval.inSet {
			return interval.interval.Start()
		}
	}
	log.Panic("cannot take min from empty interval set")
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

func appendSlices(slice1 *[]AugmentedInterval, slice2 []AugmentedInterval) {
	for _, el := range slice2 {
		*slice1 = append(*slice1, el)
	}
}

// AddAugmentedInterval adds a new interval/hole  to the set,
// and updates the implying rules accordingly
func (c *AugmentedCanonicalSet) AddAugmentedInterval(v AugmentedInterval) {
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
	appendSlices(&result, set[0:left])

	// handle the left-hand side of the intersection of v with set
	if v.interval.Start() > set[left].interval.Start() && set[left].inSet != v.inSet {
		// split set[left] into two intervals, while the implying rules of the second interval should get the new value (from v)
		new1 := AugmentedInterval{interval: interval.New(set[left].interval.Start(), v.interval.Start()-1),
			inSet: set[left].inSet, implyingRules: set[left].implyingRules.Copy()}
		new2 := AugmentedInterval{interval: interval.New(v.interval.Start(), min(set[left].interval.End(), v.interval.End())),
			inSet: v.inSet, implyingRules: v.implyingRules.Copy()}
		result = append(result, new1, new2)
		left++
	}
	for ind := left; ind <= right; ind++ {
		if set[ind].inSet == v.inSet {
			// this interval is not impacted by v - don't change its implying rules
			result = append(result, set[ind])
		} else {
			if ind == right && v.interval.End() < set[right].interval.End() {
				break // this is the corner case handled following the loop below
			}
			result = append(result, AugmentedInterval{interval: set[ind].interval, inSet: v.inSet, implyingRules: v.implyingRules.Copy()})
		}
	}
	// handle the right-hand side of the intersection of v with set
	if v.interval.End() < set[right].interval.End() && set[right].inSet != v.inSet {
		// split set[right] into two intervals, while the implying rules of the first interval should get the new value (from v)
		if left < right || (left == right && v.interval.Start() == set[left].interval.Start()) {
			// a special case when left==right (i.e., v is included in one interval from set) was already handled
			// at the lef-hand side of the intersection of v with set
			new1 := AugmentedInterval{interval: interval.New(set[right].interval.Start(), v.interval.End()),
				inSet: v.inSet, implyingRules: v.implyingRules.Copy()}
			result = append(result, new1)
		}
		new2 := AugmentedInterval{interval: interval.New(v.interval.End()+1, set[right].interval.End()),
			inSet: set[right].inSet, implyingRules: set[right].implyingRules.Copy()}
		result = append(result, new2)
	}

	// copy right-end intervals not impacted by v
	appendSlices(&result, set[right+1:])
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
// it updates implying rules of 'c' by those of 'other' only for values that get changed in 'c'
func (c *AugmentedCanonicalSet) Union(other *AugmentedCanonicalSet) *AugmentedCanonicalSet {
	res := c.Copy()
	if c == other {
		return res
	}
	for _, v := range other.intervalSet {
		if v.inSet {
			res.AddAugmentedInterval(v)
		}
	}
	return res
}

// Copy returns a new copy of the CanonicalSet object
func (c *AugmentedCanonicalSet) Copy() *AugmentedCanonicalSet {
	return &AugmentedCanonicalSet{intervalSet: slices.Clone(c.intervalSet)}
}

func (c *AugmentedCanonicalSet) Contains(n int64) bool {
	return NewAugmentedSetFromInterval(NewAugmentedInterval(n, n, true)).ContainedIn(c)
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
	res := NewAugmentedCanonicalSet()
	for _, left := range c.intervalSet {
		if !left.inSet {
			continue
		}
		for _, right := range other.intervalSet {
			if !right.inSet {
				continue
			}
			intersection := left.interval.Intersect(right.interval)
			if intersection.IsEmpty() {
				continue
			}
			toAdd := NewAugmentedInterval(intersection.Start(), intersection.End(), true)
			toAdd.implyingRules = left.implyingRules.Copy()
			toAdd.implyingRules.Union(right.implyingRules)
			res.AddAugmentedInterval(toAdd)
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
		return NewAugmentedCanonicalSet()
	}
	res := c.Copy()
	for _, interval := range other.intervalSet {
		if interval.inSet {
			hole := interval
			hole.inSet = false
			res.AddAugmentedInterval(hole)
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

func NewAugmentedSetFromInterval(augInt AugmentedInterval) *AugmentedCanonicalSet {
	result := NewAugmentedCanonicalSet()
	result.AddAugmentedInterval(augInt)
	return result
}

func (c *AugmentedCanonicalSet) GetEquivalentCanonicalAugmentedSet() *AugmentedCanonicalSet {
	res := NewAugmentedCanonicalSet()
	interval, index := c.nextIncludedInterval(0)
	for index != NoIndex {
		res.AddAugmentedInterval(NewAugmentedInterval(interval.Start(), interval.End(), true))
		interval, index = c.nextIncludedInterval(index + 1)
	}
	return res
}
