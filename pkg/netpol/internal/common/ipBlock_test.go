package common

import (
	"fmt"
	"testing"
)

func TestIpBlockBasic(t *testing.T) {
	ipb, err := NewIPBlock("10.0.0.0/8", []string{"10.2.3.4/32"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	res := ipb.ToIPRanges()
	fmt.Printf("%v", res)
}

func TestDisjointIpBlocks(t *testing.T) {
	ip1, _ := NewIPBlock("10.0.0.0/8", []string{})
	ip2, _ := NewIPBlock("10.2.3.4/32", []string{})
	set1 := []*IPBlock{ip1}
	set2 := []*IPBlock{ip2}
	res := DisjointIPBlocks(set1, set2)
	resStr := ""
	for _, ipb := range res {
		fmt.Printf("%v", ipb.ToIPRanges())
		resStr += ipb.ToIPRanges() + ","
	}
	fmt.Printf("%v", resStr)
}
