package common

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

const (
	ipByte   = 0xff
	ipShift0 = 24
	ipShift1 = 16
	ipShift2 = 8
	ipBase   = 10
	ipMask   = 0xffffffff
)

// IPBlock captures a set of ip ranges
type IPBlock struct {
	ipRange CanonicalIntervalSet
}

// ToIPRanges returns a string of the ip ranges in the current IPBlock object
func (b *IPBlock) ToIPRanges() string {
	IPRanges := make([]string, len(b.ipRange.IntervalSet))
	for index := range b.ipRange.IntervalSet {
		startIP := InttoIP4(b.ipRange.IntervalSet[index].Start)
		endIP := InttoIP4(b.ipRange.IntervalSet[index].End)
		IPRanges[index] = rangeIPstr(startIP, endIP)
	}
	return strings.Join(IPRanges, ",")
}

// IsIPAddress returns true if IPBlock object is a range of exactly one ip address from input
func (b *IPBlock) IsIPAddress(ipAddress string) bool {
	ipRanges := b.ToIPRanges()
	return ipRanges == rangeIPstr(ipAddress, ipAddress)
}

func rangeIPstr(start, end string) string {
	return fmt.Sprintf("%v-%v", start, end)
}

// Copy returns a new copy of IPBlock object
func (b *IPBlock) Copy() *IPBlock {
	res := &IPBlock{}
	res.ipRange = b.ipRange.Copy()
	return res
}

func (b *IPBlock) ipCount() int {
	res := 0
	for _, r := range b.ipRange.IntervalSet {
		res += int(r.End) - int(r.Start) + 1
	}
	return res
}

// Split returns a set of IpBlock objects, each with a single range of ips
func (b *IPBlock) Split() []*IPBlock {
	res := make([]*IPBlock, len(b.ipRange.IntervalSet))
	for index, ipr := range b.ipRange.IntervalSet {
		newBlock := IPBlock{}
		newBlock.ipRange.IntervalSet = append(newBlock.ipRange.IntervalSet, Interval{Start: ipr.Start, End: ipr.End})
		res[index] = &newBlock
	}
	return res
}

// InttoIP4 returns a string of an ip address from an input integer ip value
func InttoIP4(ipInt int64) string {
	// need to do two bit shifting and “0xff” masking
	b0 := strconv.FormatInt((ipInt>>ipShift0)&ipByte, ipBase)
	b1 := strconv.FormatInt((ipInt>>ipShift1)&ipByte, ipBase)
	b2 := strconv.FormatInt((ipInt>>ipShift2)&ipByte, ipBase)
	b3 := strconv.FormatInt((ipInt & ipByte), ipBase)
	return b0 + "." + b1 + "." + b2 + "." + b3
}

// DisjointIPBlocks returns an IPBlock of disjoint ip ranges from 2 input IPBlock objects
func DisjointIPBlocks(set1, set2 []*IPBlock) []*IPBlock {
	ipbList := []*IPBlock{}
	for _, ipb := range set1 {
		ipbList = append(ipbList, ipb.Copy())
	}
	for _, ipb := range set2 {
		ipbList = append(ipbList, ipb.Copy())
	}
	// sort ipbList by ip_count per ipblock
	sort.Slice(ipbList, func(i, j int) bool {
		return ipbList[i].ipCount() < ipbList[j].ipCount()
	})
	// making sure the resulting list does not contain overlapping ipBlocks
	blocksWithNoOverlaps := []*IPBlock{}
	for _, ipb := range ipbList {
		blocksWithNoOverlaps = addIntervalToList(ipb, blocksWithNoOverlaps)
	}

	res := blocksWithNoOverlaps
	if len(res) == 0 {
		newAll, _ := NewIPBlock("0.0.0.0/0", []string{})
		res = append(res, newAll)
	}
	return res
}

// addIntervalToList is used for computation of DisjointIPBlocks
func addIntervalToList(ipbNew *IPBlock, ipbList []*IPBlock) []*IPBlock {
	toAdd := []*IPBlock{}
	for idx, ipb := range ipbList {
		if !ipb.ipRange.Overlaps(&ipbNew.ipRange) {
			continue
		}
		intersection := ipb.Copy()
		intersection.ipRange.Intersection(ipbNew.ipRange)
		ipbNew.ipRange.Subtraction(intersection.ipRange)
		if !ipb.ipRange.Equal(intersection.ipRange) {
			toAdd = append(toAdd, intersection)
			ipbList[idx].ipRange.Subtraction(intersection.ipRange)
		}
		if len(ipbNew.ipRange.IntervalSet) == 0 {
			break
		}
	}
	ipbList = append(ipbList, ipbNew.Split()...)
	ipbList = append(ipbList, toAdd...)
	return ipbList
}

// NewIPBlock returns an IPBlock object from input cidr str an exceptions cidr str
func NewIPBlock(cidr string, exceptions []string) (*IPBlock, error) {
	res := IPBlock{ipRange: CanonicalIntervalSet{}}
	interval, err := cidrToInterval(cidr)
	if err != nil {
		return nil, err
	}
	res.ipRange.AddInterval(*interval)
	for i := range exceptions {
		intervalHole, err := cidrToInterval(exceptions[i])
		if err != nil {
			return nil, err
		}
		res.ipRange.AddHole(*intervalHole)
	}
	return &res, nil
}

// NewIPBlockFromIPAddress returns an IPBlock object from input ip address str
func NewIPBlockFromIPAddress(ipAddress string) (*IPBlock, error) {
	return NewIPBlock(ipAddress+"/32", []string{})
}

func cidrToIPRange(cidr string) (beginning, end int64, err error) {
	// convert string to IPNet struct
	_, ipv4Net, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, 0, err
	}

	// convert IPNet struct mask and address to uint32
	// network is BigEndian
	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
	start := binary.BigEndian.Uint32(ipv4Net.IP)

	// find the final address
	finish := (start & mask) | (mask ^ ipMask)
	return int64(start), int64(finish), nil
}

func cidrToInterval(cidr string) (*Interval, error) {
	start, end, err := cidrToIPRange(cidr)
	if err != nil {
		return nil, err
	}
	return &Interval{Start: start, End: end}, nil
}

func (b *IPBlock) ContainedIn(other *IPBlock) bool {
	return b.ipRange.ContainedIn(other.ipRange)
}
