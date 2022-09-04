package k8s

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strconv"
	// "inet.af/netaddr"
)

const (
	ipByte   = 0xff
	ipShift0 = 24
	ipShift1 = 16
	ipShift2 = 8
	ipBase   = 10
	ipMask   = 0xffffffff
)

type IPBlock struct {
	ipRange CanonicalIntervalSet
}

func (b *IPBlock) ToIPRanges() string {
	res := ""
	for index := range b.ipRange.IntervalSet {
		startIP := InttoIP4(b.ipRange.IntervalSet[index].Start)
		endIP := InttoIP4(b.ipRange.IntervalSet[index].End)
		res += fmt.Sprintf("%v-%v,", startIP, endIP)
	}
	return res
}

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

// return a set of IpBlock objects, each with a single range of ips
func (b *IPBlock) split() []*IPBlock {
	res := []*IPBlock{}
	for _, ipr := range b.ipRange.IntervalSet {
		newBlock := IPBlock{}
		newBlock.ipRange.IntervalSet = append(newBlock.ipRange.IntervalSet, Interval{Start: ipr.Start, End: ipr.End})
		res = append(res, &newBlock)
	}
	return res
}

//revive:disable:add-constant
func InttoIP4(ipInt int64) string {
	// need to do two bit shifting and “0xff” masking
	b0 := strconv.FormatInt((ipInt>>ipShift0)&ipByte, ipBase)
	b1 := strconv.FormatInt((ipInt>>ipShift1)&ipByte, ipBase)
	b2 := strconv.FormatInt((ipInt>>ipShift2)&ipByte, ipBase)
	b3 := strconv.FormatInt((ipInt & ipByte), ipBase)
	return b0 + "." + b1 + "." + b2 + "." + b3
}

//revive:enable:add-constant

// TODO: support allowed_connections considering an ipBlock (cidr), not only ip address
// TODO: generate tests for disjoint ip blocks (unit tests, and per netpols)
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
	ipbList = append(ipbList, ipbNew.split()...)
	ipbList = append(ipbList, toAdd...)
	return ipbList
}

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

func cidrToIPRange(cidr string) (int64, int64, error) {
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

// func NewIpBlock(cidr string, exceptions []string) *IpBlock {
/*var b netaddr.IPSetBuilder
b.AddPrefix(netaddr.MustParseIPPrefix("10.0.0.0/8"))
b.Remove(netaddr.MustParseIP("10.2.3.4"))
s, _ := b.IPSet()
fmt.Println(s.Ranges())
fmt.Println(s.Prefixes())*/
// }

// func cidrTo

// func DisjointIpBlocks()
