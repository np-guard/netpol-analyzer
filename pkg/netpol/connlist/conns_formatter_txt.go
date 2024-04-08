package connlist

import (
	"sort"
	"strings"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// formatText: implements the connsFormatter interface for txt output format
type formatText struct {
	// PeerToConnsFromIPs map from real peer.String() to its ingress connections from ip-blocks lines
	// extracted from the []Peer2PeerConnection conns to be appended also to the exposure-analysis output
	PeerToConnsFromIPs map[string][]string
	// peerToConnsToIPs map from real peer.String() to its egress connections to ip-blocks lines
	// extracted from the []Peer2PeerConnection conns to be appended also to the exposure-analysis output
	peerToConnsToIPs map[string][]string
}

// writeOutput returns a textual string format of connections from list of Peer2PeerConnection objects,
// and exposure analysis results if exist
func (t *formatText) writeOutput(conns []Peer2PeerConnection, exposureConns []ExposedPeer) (string, error) {
	exposureFlag := len(exposureConns) > 0
	res := t.writeConnlistOutput(conns, exposureFlag)
	if !exposureFlag {
		return res, nil
	}
	// else append exposure analysis results:
	if res != "" {
		res += "\n\n"
	}
	res += t.writeExposureOutput(exposureConns)
	return res, nil
}

func (t *formatText) writeConnlistOutput(conns []Peer2PeerConnection, saveIPConns bool) string {
	connLines := make([]string, len(conns))
	if saveIPConns {
		t.peerToConnsToIPs = make(map[string][]string)
		t.PeerToConnsFromIPs = make(map[string][]string)
	}
	for i, conn := range conns {
		connLines[i] = formSingleP2PConn(conns[i]).string()
		// if we have exposure analysis results, also check if src/dst is an IP and store the connection
		if saveIPConns {
			if conn.Src().IsPeerIPType() {
				t.PeerToConnsFromIPs[conn.Dst().String()] = append(t.PeerToConnsFromIPs[conn.Dst().String()], connLines[i])
			}
			if conn.Dst().IsPeerIPType() {
				t.peerToConnsToIPs[conn.Src().String()] = append(t.peerToConnsToIPs[conn.Src().String()], connLines[i])
			}
		}
	}
	sort.Strings(connLines)
	return strings.Join(connLines, newLineChar)
}

func (t *formatText) writeExposureOutput(exposureResults []ExposedPeer) string {
	// sorting the exposed peers slice so we get unique sorted output by Peer.String()
	sortedExposureResults := sortExposedPeerSlice(exposureResults)
	exposureLines := make([]string, 0)
	unprotectedLines := make([]string, 0)
	for _, ep := range sortedExposureResults {
		// ingress and egress lines per peer, internally sorted
		ingressLines, ingressUnprotectedLine := t.getPeerIngressExposureLines(ep)
		exposureLines = append(exposureLines, ingressLines...)
		if ingressUnprotectedLine != "" {
			unprotectedLines = append(unprotectedLines, ingressUnprotectedLine)
		}
		egressLines, egressUnprotectedLine := t.getPeerEgressExposureLines(ep)
		exposureLines = append(exposureLines, egressLines...)
		if egressUnprotectedLine != "" {
			unprotectedLines = append(unprotectedLines, egressUnprotectedLine)
		}
	}
	res := "Exposure Analysis Result:\n"
	res += strings.Join(exposureLines, newLineChar)
	if len(unprotectedLines) > 0 {
		res += "\n\nWorkloads which are not protected by network policies:\n"
		sort.Strings(unprotectedLines)
		res += strings.Join(unprotectedLines, newLineChar)
	}
	return res
}

//nolint:dupl //same functionality but on different variables of exposedPeer and formatText so prefer to split
func (t *formatText) getPeerIngressExposureLines(ep ExposedPeer) (ingressLines []string, ingressUnprotectedLine string) {
	// if a peer is not protected, two lines are to be added to exposure analysis result:
	// 1. all conns with entire cluster (added here)
	// 2. all conns with ip-blocks (all destinations); for sure found in the ip conns map so will be added automatically
	// also unprotected line will be added
	if !ep.IsProtectedByIngressNetpols() {
		ingressLines = append(ingressLines, formSingleExposureConn(ep.ExposedPeer().String(), entireCluster,
			common.MakeConnectionSet(true), true).string())
		ingressUnprotectedLine = ep.ExposedPeer().String() + " is not protected on Ingress"
	} else { // protected
		for _, data := range ep.IngressExposure() {
			// for txt output append the string of the singleConnFields
			ingressLines = append(ingressLines, formExposureItemAsSingleConnFiled(ep.ExposedPeer(), data, true).string())
		}
	}
	// append ingress ip conns to this peer
	if ipConns, ok := t.PeerToConnsFromIPs[ep.ExposedPeer().String()]; ok {
		ingressLines = append(ingressLines, ipConns...)
	}
	sort.Strings(ingressLines)
	return ingressLines, ingressUnprotectedLine
}

//nolint:dupl //same functionality but on different variables of exposedPeer and formatText so prefer to split
func (t *formatText) getPeerEgressExposureLines(ep ExposedPeer) (egressLines []string, egressUnprotectedLine string) {
	// if a peer is not protected, two lines are to be added to exposure analysis result:
	// 1. all conns with entire cluster (added here)
	// 2. all conns with ip-blocks (all destinations); for sure found in the ip conns map so will be added automatically
	// also unprotected line will be added
	if !ep.IsProtectedByEgressNetpols() {
		egressLines = append(egressLines, formSingleExposureConn(ep.ExposedPeer().String(), entireCluster,
			common.MakeConnectionSet(true), false).string())
		egressUnprotectedLine = ep.ExposedPeer().String() + " is not protected on Egress"
	} else { // protected
		for _, data := range ep.EgressExposure() {
			// for txt output append the string of the singleConnFields
			egressLines = append(egressLines, formExposureItemAsSingleConnFiled(ep.ExposedPeer(), data, false).string())
		}
	}
	// append egress ip conns to this peer
	if ipConns, ok := t.peerToConnsToIPs[ep.ExposedPeer().String()]; ok {
		egressLines = append(egressLines, ipConns...)
	}
	sort.Strings(egressLines)
	return egressLines, egressUnprotectedLine
}

func sortExposedPeerSlice(exposedPeers []ExposedPeer) []ExposedPeer {
	sort.Slice(exposedPeers, func(i, j int) bool {
		return exposedPeers[i].ExposedPeer().String() < exposedPeers[j].ExposedPeer().String()
	})
	return exposedPeers
}
