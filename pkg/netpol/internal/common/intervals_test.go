package common

import (
	"testing"

	v1 "k8s.io/api/core/v1"
)

func TestAddInterval(t *testing.T) {
	a := CanonicalIntervalSet{}
	a.AddInterval(Interval{Start: 1, End: 10})
	x := a.String()
	t.Logf("res: %v\n", x)
	b := CanonicalIntervalSet{IntervalSet: []Interval{{Start: 1, End: 10}}}
	if !b.Equal(a) {
		t.Fatalf("error")
	}

	a = CanonicalIntervalSet{}
	a.AddInterval(Interval{Start: 1, End: 2})
	a.AddInterval(Interval{Start: 5, End: 6})
	a.AddInterval(Interval{Start: 3, End: 4})
	x = a.String()
	t.Logf("res: %v\n", x)
	b = CanonicalIntervalSet{IntervalSet: []Interval{{Start: 1, End: 6}}}
	if !b.Equal(a) {
		t.Fatalf("error")
	}

	a = CanonicalIntervalSet{}
	a.AddInterval(Interval{Start: 1, End: 5})
	a.AddInterval(Interval{Start: 3, End: 8})
	x = a.String()
	t.Logf("res: %v\n", x)
	b = CanonicalIntervalSet{IntervalSet: []Interval{{Start: 1, End: 8}}}
	if !b.Equal(a) {
		t.Fatalf("error")
	}

	a.AddHole(Interval{Start: 3, End: 4})
	t.Logf("res: %v\n", a.String())
	b = CanonicalIntervalSet{IntervalSet: []Interval{{Start: 1, End: 2}, {Start: 5, End: 8}}}
	if !b.Equal(a) {
		t.Fatalf("error")
	}
}

func TestPortSet(t *testing.T) {
	a1 := MakePortSet(false)
	t.Logf("res: %v\n", a1.Ports.String())
	a2 := MakePortSet(true)
	t.Logf("res: %v\n", a2.Ports.String())
}

func TestIntervalUnion(t *testing.T) {
	a := CanonicalIntervalSet{}
	a.AddInterval(Interval{Start: 1, End: 10})
	b := CanonicalIntervalSet{}
	a.AddInterval(Interval{Start: 12, End: 20})
	a.Union(b)
	c := CanonicalIntervalSet{}
	c.AddInterval(Interval{Start: 1, End: 10})
	c.AddInterval(Interval{Start: 12, End: 20})
	if !c.Equal(a) {
		t.Fatalf("error")
	}
}

func TestConnectionSet(t *testing.T) {
	a1 := MakePortSet(false)
	a1.AddPortRange(80, 80)
	a := MakeConnectionSet(false)
	a.AddConnection(v1.ProtocolTCP, a1)
	b := MakeConnectionSet(false)
	b.Union(a)
	if !b.Equal(a) {
		t.Fatalf("error")
	}
	bStr := b.String()
	aStr := a.String()
	if aStr != bStr {
		t.Fatalf("error")
	}
}
