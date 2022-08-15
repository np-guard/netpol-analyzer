package k8s

import (
	"fmt"
)

type Interval struct {
	Start int64
	End   int64
}

func (i *Interval) String() string {
	//return "[" + strconv.Itoa(i.Start) + "-" + strconv.Itoa(i.End) + "]"
	return fmt.Sprintf("[%v-%v]", i.Start, i.End)
}

func (i *Interval) Equal(x Interval) bool {
	return i.Start == x.Start && i.End == x.End
}

func (i *Interval) Lt(x Interval) bool {
	return i.Start < x.Start || (i.Start == x.Start && i.End < x.End)
}

func (i *Interval) overlaps(other Interval) bool {
	return other.End >= i.Start && other.Start <= i.End
}

func (i *Interval) touches(other Interval) bool {
	if i.Start > other.End {
		return i.Start == other.End+1
	}
	if other.Start > i.End {
		return other.Start == i.End+1
	}
	return false
}

func (i *Interval) isSubset(other Interval) bool {
	return other.Start <= i.Start && other.End >= i.End
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

//returns a list with up to 2 intervals
func (i *Interval) subtract(other Interval) []Interval {
	if !i.overlaps(other) {
		return []Interval{*i}
	}
	if i.isSubset(other) {
		return []Interval{}
	}
	if i.Start < other.Start && i.End > other.End {
		// self is split into two ranges by other
		return []Interval{{Start: i.Start, End: other.Start - 1}, {Start: other.End + 1, End: i.End}}
	}
	if i.Start < other.Start {
		return []Interval{{Start: i.Start, End: min(i.End, other.Start-1)}}
	}
	return []Interval{{Start: max(i.Start, other.End+1), End: i.End}}
}

func (i *Interval) intersection(other Interval) []Interval {
	maxStart := max(i.Start, other.Start)
	minEnd := min(i.End, other.End)
	if minEnd < maxStart {
		return []Interval{}
	}
	return []Interval{{Start: maxStart, End: minEnd}}

}

type CanonicalIntervalSet struct {
	IntervalSet []Interval //sorted list of non-overlapping intervals
}

func (c *CanonicalIntervalSet) IsEmpty() bool {
	return len(c.IntervalSet) == 0
}

func (c *CanonicalIntervalSet) Equal(other CanonicalIntervalSet) bool {
	if len(c.IntervalSet) != len(other.IntervalSet) {
		return false
	}
	for index := range c.IntervalSet {
		if !(c.IntervalSet[index].Equal(other.IntervalSet[index])) {
			return false
		}
	}
	return true

}

func (c *CanonicalIntervalSet) findIntervalLeft(interval Interval) int {
	if c.IsEmpty() {
		return -1
	}
	low := 0
	high := len(c.IntervalSet)
	for {
		if low == high {
			break
		}
		mid := (low + high) / 2
		if c.IntervalSet[mid].End < interval.Start-1 {
			if mid == len(c.IntervalSet)-1 || c.IntervalSet[mid+1].End >= interval.Start-1 {
				return mid
			}
			low = mid + 1
		} else {
			high = mid
		}
	}
	if low == len(c.IntervalSet) {
		low -= 1
	}
	if c.IntervalSet[low].End >= interval.Start-1 {
		return -1
	}
	return low
}

func (c *CanonicalIntervalSet) findIntervalRight(interval Interval) int {
	if c.IsEmpty() {
		return -1
	}
	low := 0
	high := len(c.IntervalSet)
	for {
		if low == high {
			break
		}
		mid := (low + high) / 2
		if c.IntervalSet[mid].Start > interval.End+1 {
			if mid == 0 || c.IntervalSet[mid-1].Start <= interval.End+1 {
				return mid
			}
			high = mid
		} else {
			low = mid + 1
		}
	}
	if low == len(c.IntervalSet) {
		low -= 1
	}
	if c.IntervalSet[low].Start <= interval.End+1 {
		return -1
	}
	return low
}

func insert(array []Interval, element Interval, i int) []Interval {
	return append(array[:i], append([]Interval{element}, array[i:]...)...)
}

func (c *CanonicalIntervalSet) AddInterval(intervalToAdd Interval) {
	if c.IsEmpty() {
		c.IntervalSet = append(c.IntervalSet, intervalToAdd)
		return
	}
	left := c.findIntervalLeft(intervalToAdd)
	right := c.findIntervalRight(intervalToAdd)

	//interval_to_add has no overlapping/touching intervals between left to right
	if left >= 0 && right >= 0 && right-left == 1 {
		c.IntervalSet = insert(c.IntervalSet, intervalToAdd, left+1)
		return
	}

	//interval_to_add has no overlapping/touching intervals and is smaller than first interval
	if left == -1 && right == 0 {
		c.IntervalSet = insert(c.IntervalSet, intervalToAdd, 0)
		return
	}

	//interval_to_add has no overlapping/touching intervals and is greater than last interval
	if right == -1 && left == len(c.IntervalSet)-1 {
		c.IntervalSet = append(c.IntervalSet, intervalToAdd)
		return
	}

	//update left/right indexes to be the first potential overlapping/touching intervals from left/right
	left += 1
	if right >= 0 {
		right -= 1
	} else {
		right = len(c.IntervalSet) - 1
	}
	//check which of left/right is overlapping/touching interval_to_add
	left_overlaps := c.IntervalSet[left].overlaps(intervalToAdd) || c.IntervalSet[left].touches(intervalToAdd)
	right_overlaps := c.IntervalSet[right].overlaps(intervalToAdd) || c.IntervalSet[right].touches(intervalToAdd)
	new_interval_Start := intervalToAdd.Start
	if left_overlaps && c.IntervalSet[left].Start < new_interval_Start {
		new_interval_Start = c.IntervalSet[left].Start
	}
	new_interval_End := intervalToAdd.End
	if right_overlaps && c.IntervalSet[right].End > new_interval_End {
		new_interval_End = c.IntervalSet[right].End
	}
	newInterval := Interval{Start: new_interval_Start, End: new_interval_End}
	tmp := c.IntervalSet[right+1:]
	c.IntervalSet = append(c.IntervalSet[:left], newInterval)
	c.IntervalSet = append(c.IntervalSet, tmp...)

}

func (c *CanonicalIntervalSet) AddHole(hole Interval) {
	newIntervalSet := []Interval{}
	for _, interval := range c.IntervalSet {
		newIntervalSet = append(newIntervalSet, interval.subtract(hole)...)
	}
	c.IntervalSet = newIntervalSet
}

func (c *CanonicalIntervalSet) String() string {
	if c.IsEmpty() {
		return "Empty"
	}
	res := ""
	for _, interval := range c.IntervalSet {
		res += fmt.Sprintf("%v", interval.Start) //strconv.Itoa(interval.Start)
		if interval.Start != interval.End {
			res += "-" + fmt.Sprintf("%v", interval.End) //strconv.Itoa(interval.End)
		}
		res += ","
	}
	return res[:len(res)-1]
}

func (c *CanonicalIntervalSet) Union(other CanonicalIntervalSet) {
	for _, interval := range other.IntervalSet {
		c.AddInterval(interval)
	}
}

func (c *CanonicalIntervalSet) Copy() CanonicalIntervalSet {
	return CanonicalIntervalSet{IntervalSet: append([]Interval(nil), c.IntervalSet...)}
}

func Union(a, b CanonicalIntervalSet) CanonicalIntervalSet {
	res := a.Copy()
	res.Union(b)
	return res
}

func (c *CanonicalIntervalSet) ContainedIn(other CanonicalIntervalSet) bool {
	if len(c.IntervalSet) == 1 && len(other.IntervalSet) == 1 {
		return c.IntervalSet[0].isSubset(other.IntervalSet[0])
	}
	for _, interval := range c.IntervalSet {
		left := other.findIntervalLeft(interval)
		if left == len(other.IntervalSet)-1 {
			return false
		}
		if !interval.isSubset(other.IntervalSet[left+1]) {
			return false
		}
	}
	return true
}

func (c *CanonicalIntervalSet) Intersection(other CanonicalIntervalSet) {
	newIntervalSet := []Interval{}
	for _, interval := range c.IntervalSet {
		for _, otherInterval := range other.IntervalSet {
			newIntervalSet = append(newIntervalSet, interval.intersection(otherInterval)...)
		}
	}
	c.IntervalSet = newIntervalSet
}

func (c *CanonicalIntervalSet) Overlaps(other *CanonicalIntervalSet) bool {
	for _, selfInterval := range c.IntervalSet {
		for _, otherInterval := range other.IntervalSet {
			if selfInterval.overlaps(otherInterval) {
				return true
			}
		}
	}
	return false
}

func (c *CanonicalIntervalSet) Subtraction(other CanonicalIntervalSet) {
	for _, i := range other.IntervalSet {
		c.AddHole(i)
	}
}
