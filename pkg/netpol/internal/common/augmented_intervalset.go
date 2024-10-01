/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"log"
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

type AugmentedInterval struct {
	interval      interval.Interval
	inSet         bool
	implyingRules *ImplyingRulesType
}

func NewAugmentedInterval(start, end int64, inSet bool) AugmentedInterval {
	return AugmentedInterval{interval: interval.New(start, end), inSet: inSet, implyingRules: &ImplyingRulesType{}}
}

func NewAugmentedIntervalWithRule(start, end int64, inSet bool, rule string) AugmentedInterval {
	return AugmentedInterval{interval: interval.New(start, end), inSet: inSet, implyingRules: &ImplyingRulesType{rule: true}}
}

func NewAugmentedIntervalWithRules(start, end int64, inSet bool, rules *ImplyingRulesType) AugmentedInterval {
	return AugmentedInterval{interval: interval.New(start, end), inSet: inSet, implyingRules: rules.Copy()}
}

// CanonicalSet is a set of int64 integers, implemented using an ordered slice of non-overlapping, non-touching interval
// the intervals should include both included intervals and holes; i.e., start of every interval is the end of a previous interval incremented by 1
// the last interval should always end with '-1' and should have inSet being false (thus representing a hole till the end of the range)
type AugmentedCanonicalSet struct {
	intervalSet []AugmentedInterval
}

func NewAugmentedCanonicalSet() *AugmentedCanonicalSet {
	return &AugmentedCanonicalSet{
		intervalSet: []AugmentedInterval{
			NewAugmentedInterval(0, -1, false), // the full range 'hole'
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
	return c.intervalSet[0].interval.Start()
}

// IsEmpty returns true if the AugmentedCanonicalSet is semantically empty (i.e., at least one 'inSet' interval)
func (c *AugmentedCanonicalSet) IsEmpty() bool {
	for _, interval := range c.intervalSet {
		if interval.inSet {
			return false
		}
	}
	return true
}

func (c *AugmentedCanonicalSet) CalculateSize() int64 {
	var res int64 = 0
	for _, r := range c.intervalSet {
		res += r.interval.Size()
	}
	return res
}

// nextIncludedInterval finds an interval included in set (not hole), starting from fromInd.
// if there are a few continuous in set intervals, it will return the union of all of them.
// it returns the found (potentially extended) interval, and the biggest index contributing to the result
func (c *AugmentedCanonicalSet) nextIncludedInterval(fromInd int) (interval.Interval, int) {
	start := fromInd
	for start < len(c.intervalSet) && !c.intervalSet[start].inSet {
		start++
	}
	if start >= len(c.intervalSet) {
		return interval.New(0, -1), -1
	}
	end := start
	for end < len(c.intervalSet) && c.intervalSet[end].inSet {
		end++
	}
	return interval.New(c.intervalSet[start].interval.Start(), c.intervalSet[end].interval.End()), end
}

// Equal returns true if the AugmentedCanonicalSet semantically equals the other AugmentedCanonicalSet;
// only numeric intervals are compared; the implying rules are not compared.
func (c *AugmentedCanonicalSet) Equal(other *AugmentedCanonicalSet) bool {
	if c == other {
		return true
	}
	currThisInd := 0
	currOtherInd := 0

	for currThisInd != -1 {
		thisInterval, thisInd := c.nextIncludedInterval(currThisInd)
		otherInterval, otherInd := other.nextIncludedInterval(currOtherInd)
		if (thisInd == -1) != (otherInd == -1) {
			return false
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
func (c *AugmentedCanonicalSet) AddAugmentedInterval(v AugmentedInterval) {
	if v.interval.IsEmpty() {
		return
	}
	set := c.intervalSet
	left := sort.Search(len(set), func(i int) bool {
		return set[i].interval.End() >= v.interval.Start()
	})
	right := sort.Search(len(set), func(j int) bool {
		return set[j].interval.Start() > v.interval.End()
	})
	var result []AugmentedInterval
	// copy left-end intervals not impacted by v
	copy(result, set[0:left])
	if v.interval.Start() > set[left].interval.Start() && set[left].inSet != v.inSet {
		// split set[left] into two intervals, while the implying rules of the second interval should get the new value (from v)
		new1 := AugmentedInterval{interval: interval.New(set[left].interval.Start(), v.interval.Start()-1), inSet: set[left].inSet, implyingRules: set[left].implyingRules.Copy()}
		new2 := AugmentedInterval{interval: interval.New(v.interval.Start(), set[left].interval.End()), inSet: v.inSet, implyingRules: v.implyingRules.Copy()}
		result = append(result, new1, new2)
		left++
	}
	for ind := left; ind < right; ind++ {
		if set[ind].inSet == v.inSet {
			// this interval is not impacted by v - don't change its implying rules
			result = append(result, set[ind])
		} else {
			result = append(result, AugmentedInterval{interval: set[ind].interval, inSet: v.inSet, implyingRules: v.implyingRules.Copy()})
		}
	}
	// copy right-end intervals not impacted by v
	copy(result[len(result):], set[right:])
	c.intervalSet = result
	// TODO - optimization: unify subsequent intervals with equal inSet and implyingRules fields
}

// String returns a string representation of the current CanonicalSet object
func (c *AugmentedCanonicalSet) String() string {
	if c.IsEmpty() {
		return "Empty"
	}
	res := ""
	for _, interval := range c.intervalSet {
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
		res.AddAugmentedInterval(v)
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
	for currThisInd != -1 {
		thisInterval, thisInd := c.nextIncludedInterval(currThisInd)
		otherInterval, otherInd := other.nextIncludedInterval(currOtherInd)
		if thisInd == -1 {
			return true // end of this interval set
		} else if otherInd == -1 {
			return false // end of other interval set, but still have uncovered interval in this set
		} else if thisInterval.IsSubset(otherInterval) {
			// this interval is included in other; move to next intervals
			currThisInd = thisInd + 1
			currOtherInd = otherInd + 1
			continue
		} else if thisInterval.Overlap(otherInterval) {
			// only part of this interval is contained
			return false
		} else if thisInterval.End() < otherInterval.Start() {
			// this interval is not contained here
			return false
		} else { // otherInterval.End() < thisInterval.Start()
			// increment currOtherInd
			currOtherInd = otherInd + 1
		}
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
			interval := left.interval.Intersect(right.interval)
			if interval.IsEmpty() {
				continue
			}
			toAdd := NewAugmentedInterval(interval.Start(), interval.End(), true)
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
	for currThisInd != -1 {
		thisInterval, thisInd := c.nextIncludedInterval(currThisInd)
		otherInterval, otherInd := other.nextIncludedInterval(currOtherInd)
		if thisInd == -1 || otherInd == -1 {
			return false // did not find overlapping interval
		} else if thisInterval.Overlap(otherInterval) {
			return true
		} else if thisInterval.End() < otherInterval.Start() {
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
		for v := interval.interval.Start(); v <= interval.interval.End(); v++ {
			res[i] = v
			i++
		}
	}
	return res
}

func NewAugmentedSetFromInterval(interval AugmentedInterval) *AugmentedCanonicalSet {
	result := NewAugmentedCanonicalSet()
	result.AddAugmentedInterval(interval)
	return result
}
