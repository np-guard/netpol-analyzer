package eval

type Peer interface {
	Name() string
	Namespace() string
	IP() string
	IsPeerIPType() bool
	String() string
}
