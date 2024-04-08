package connlist

import (
	"fmt"
	"sort"

	"k8s.io/apimachinery/pkg/labels"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

var newLineChar = fmt.Sprintln("")

// gets the conns array and returns a sorted array of singleConnFields structs. helps with forming the json and csv outputs
func sortConnections(conns []Peer2PeerConnection) []singleConnFields {
	connItems := make([]singleConnFields, len(conns))
	for i := range conns {
		connItems[i] = formSingleP2PConn(conns[i])
	}
	sort.Slice(connItems, func(i, j int) bool {
		if connItems[i].Src != connItems[j].Src {
			return connItems[i].Src < connItems[j].Src
		}
		return connItems[i].Dst < connItems[j].Dst
	})

	return connItems
}

// connsFormatter implements output formatting in the required output format
type connsFormatter interface {
	writeOutput(conns []Peer2PeerConnection, exposureConns []ExposedPeer) (string, error)
}

// singleConnFields represents a single connection object
type singleConnFields struct {
	Src        string `json:"src"`
	Dst        string `json:"dst"`
	ConnString string `json:"conn"`
}

// string representation of the singleConnFields struct
func (c singleConnFields) string() string {
	return fmt.Sprintf("%s => %s : %s", c.Src, c.Dst, c.ConnString)
}

// formSingleP2PConn returns a string representation of single connection fields as singleConnFields object
func formSingleP2PConn(conn Peer2PeerConnection) singleConnFields {
	connStr := common.ConnStrFromConnProperties(conn.AllProtocolsAndPorts(), conn.ProtocolsAndPorts())
	return singleConnFields{Src: conn.Src().String(), Dst: conn.Dst().String(), ConnString: connStr}
}

// commonly (to be) used for exposure analysis output formatters

const entireCluster = "entire-cluster"

// formSingleExposureConn returns a representation of single exposure connection fields as singleConnFields object
func formSingleExposureConn(peer, repPeer string, conn common.Connection, isIngress bool) singleConnFields {
	connStr := conn.(*common.ConnectionSet).String()
	if isIngress {
		return singleConnFields{Src: repPeer, Dst: peer, ConnString: connStr}
	}
	return singleConnFields{Src: peer, Dst: repPeer, ConnString: connStr}
}

// formExposureItemAsSingleConnFiled returns a singleConnFields object for an item in the XgressExposureData list
func formExposureItemAsSingleConnFiled(peer Peer, exposureItem XgressExposureData, isIngress bool) singleConnFields {
	if exposureItem.IsExposedToEntireCluster() {
		return formSingleExposureConn(peer.String(), entireCluster, exposureItem.PotentialConnectivity(), isIngress)
	}
	if len(exposureItem.NamespaceLabels()) > 0 {
		return formSingleExposureConn(peer.String(), peerStrWithNsLabels(exposureItem.NamespaceLabels()),
			exposureItem.PotentialConnectivity(), isIngress)
	}
	// @todo handle podLabels
	return singleConnFields{}
}

// convertLabelsMapToString returns a string representation of the given labels map
func convertLabelsMapToString(labelsMap map[string]string) string {
	return labels.SelectorFromSet(labels.Set(labelsMap)).String()
}

// peerStrWithNsLabels returns a string representation of a potential peer with namespace labels
func peerStrWithNsLabels(nsLabels map[string]string) string {
	return "any namespace with " + convertLabelsMapToString(nsLabels)
}
