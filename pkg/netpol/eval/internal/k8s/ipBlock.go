package k8s

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strconv"
	//"inet.af/netaddr"
)

type IpBlock struct {
	ipRange CanonicalIntervalSet
}

func (b *IpBlock) ToIpRanges() string {
	res := ""
	for index := range b.ipRange.IntervalSet {
		startIp := InttoIP4(b.ipRange.IntervalSet[index].Start)
		endIp := InttoIP4(b.ipRange.IntervalSet[index].End)
		res += fmt.Sprintf("%v-%v,", startIp, endIp)
	}
	return res
}

func (b *IpBlock) Copy() *IpBlock {
	res := &IpBlock{}
	res.ipRange = b.ipRange.Copy()
	return res
}

func (b *IpBlock) ipCount() int {
	res := 0
	for _, r := range b.ipRange.IntervalSet {
		res += int(r.End) - int(r.Start) + 1
	}
	return res
}

//return a set of IpBlock objects, each with a single range of ips
func (b *IpBlock) split() []*IpBlock {
	res := []*IpBlock{}
	for _, ipr := range b.ipRange.IntervalSet {
		newBlock := IpBlock{}
		newBlock.ipRange.IntervalSet = append(newBlock.ipRange.IntervalSet, Interval{Start: ipr.Start, End: ipr.End})
		res = append(res, &newBlock)
	}
	return res

}

func InttoIP4(ipInt int64) string {

	// need to do two bit shifting and “0xff” masking
	b0 := strconv.FormatInt((ipInt>>24)&0xff, 10)
	b1 := strconv.FormatInt((ipInt>>16)&0xff, 10)
	b2 := strconv.FormatInt((ipInt>>8)&0xff, 10)
	b3 := strconv.FormatInt((ipInt & 0xff), 10)
	return b0 + "." + b1 + "." + b2 + "." + b3
}

//TODO: support allowed_connections considering an ipBlock (cidr), not only ip address
//TODO: generate tests for disjoint ip blocks (unit tests, and per netpols)
func DisjointIpBlocks(set1, set2 []*IpBlock) []*IpBlock {
	ipbList := []*IpBlock{}
	for _, ipb := range set1 {
		ipbList = append(ipbList, ipb.Copy())
	}
	for _, ipb := range set2 {
		ipbList = append(ipbList, ipb.Copy())
	}
	//sort ipbList by ip_count per ipblock
	sort.Slice(ipbList, func(i, j int) bool {
		return ipbList[i].ipCount() < ipbList[j].ipCount()
	})
	//making sure the resulting list does not contain overlapping ipBlocks
	blocksWithNoOverlaps := []*IpBlock{}
	for _, ipb := range ipbList {
		blocksWithNoOverlaps = addIntervalToList(ipb, blocksWithNoOverlaps)
	}

	res := blocksWithNoOverlaps
	if len(res) == 0 {
		newAll, _ := NewIpBlock("0.0.0.0/0", []string{})
		res = append(res, newAll)
	}
	return res
}

func addIntervalToList(ipbNew *IpBlock, ipbList []*IpBlock) []*IpBlock {
	toAdd := []*IpBlock{}
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

func NewIpBlock(cidr string, exceptions []string) (*IpBlock, error) {
	res := IpBlock{ipRange: CanonicalIntervalSet{}}
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

func cidrToIpRange(cidr string) (int64, int64, error) {
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
	finish := (start & mask) | (mask ^ 0xffffffff)
	return (int64)(start), (int64)(finish), nil
}

func cidrToInterval(cidr string) (*Interval, error) {
	start, end, err := cidrToIpRange(cidr)
	if err != nil {
		return nil, err
	}
	return &Interval{Start: start, End: end}, nil
}

//func NewIpBlock(cidr string, exceptions []string) *IpBlock {
/*var b netaddr.IPSetBuilder
b.AddPrefix(netaddr.MustParseIPPrefix("10.0.0.0/8"))
b.Remove(netaddr.MustParseIP("10.2.3.4"))
s, _ := b.IPSet()
fmt.Println(s.Ranges())
fmt.Println(s.Prefixes())*/
//}

//func cidrTo

//func DisjointIpBlocks()
