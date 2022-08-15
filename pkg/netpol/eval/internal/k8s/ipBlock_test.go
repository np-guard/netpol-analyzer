package k8s

import (
	"fmt"
	"testing"
)

func TestIpBlockBasic(t *testing.T) {
	ipb, err := NewIpBlock("10.0.0.0/8", []string{"10.2.3.4/32"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	res := ipb.ToIpRanges()
	fmt.Printf("%v", res)

}

func TestDisjointIpBlocks(t *testing.T) {
	ip1, _ := NewIpBlock("10.0.0.0/8", []string{})
	ip2, _ := NewIpBlock("10.2.3.4/32", []string{})
	set1 := []*IpBlock{ip1}
	set2 := []*IpBlock{ip2}
	res := DisjointIpBlocks(set1, set2)
	resStr := ""
	for _, ipb := range res {
		fmt.Printf("%v", ipb.ToIpRanges())
		resStr += ipb.ToIpRanges() + ","
	}
	fmt.Printf("%v", resStr)

}
