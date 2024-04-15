package connlist

import (
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// formatText: implements the connsFormatter interface for txt output format
type formatText struct {
	// connections with IP-peers should appear in both connlist and exposure-analysis output sections

	// PeerToConnsFromIPs map from real peer.String() to its ingress connections from ip-blocks
	// extracted from the []Peer2PeerConnection conns to be appended also to the exposure-analysis output
	// i.e : if connlist output contains `0.0.0.0-255.255.255.255 => ns1/workload-a : All Connections`
	// the PeerToConnsFromIPs will contain following entry: (to be written also in exposure output)
	// {ns1/workload-a: []singleConnFields{{src: 0.0.0.0-255.255.255.255, dst: ns1/workload-a, conn: All Connections},}}
	PeerToConnsFromIPs map[string][]singleConnFields

	// peerToConnsToIPs map from real peer.String() to its egress connections to ip-blocks
	// extracted from the []Peer2PeerConnection conns to be appended also to the exposure-analysis output
	peerToConnsToIPs map[string][]singleConnFields
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

// writeConnlistOutput writes the section of the connlist result of the output
func (t *formatText) writeConnlistOutput(conns []Peer2PeerConnection, saveIPConns bool) string {
	connLines := make([]string, len(conns))
	if saveIPConns {
		t.peerToConnsToIPs = make(map[string][]singleConnFields)
		t.PeerToConnsFromIPs = make(map[string][]singleConnFields)
	}
	for i := range conns {
		connLines[i] = formSingleP2PConn(conns[i]).string()
		// if we have exposure analysis results, also check if src/dst is an IP and store the connection
		if saveIPConns {
			t.saveConnsWithIPs(conns[i])
		}
	}
	sort.Strings(connLines)
	return strings.Join(connLines, newLineChar)
}

// saveConnsWithIPs gets a P2P connection; if the connection includes an IP-Peer as one of its end-points; the conn is saved in the
// matching map of the formatText maps
func (t *formatText) saveConnsWithIPs(conn Peer2PeerConnection) {
	if conn.Src().IsPeerIPType() {
		t.PeerToConnsFromIPs[conn.Dst().String()] = append(t.PeerToConnsFromIPs[conn.Dst().String()], formSingleP2PConn(conn))
	}
	if conn.Dst().IsPeerIPType() {
		t.peerToConnsToIPs[conn.Src().String()] = append(t.peerToConnsToIPs[conn.Src().String()], formSingleP2PConn(conn))
	}
}

const (
	exposureAnalysisHeader = "Exposure Analysis Result:\n"
	egressExpHeader        = "Egress Exposure:\n"
	ingressExpHeader       = "\nIngress Exposure:\n"
	unprotectedHeader      = "\nWorkloads which are not protected by network policies:\n"
)

// writeExposureOutput writes the section of the exposure-analysis result
func (t *formatText) writeExposureOutput(exposureResults []ExposedPeer) string {
	// sorting the exposed peers slice so we get unique sorted output by Peer.String()
	// and getting the max peer String length (to be used for writing fixed indented lines)
	sortedExposureResults, maxPeerStrLen := sortExposedPeerSlice(exposureResults)
	// results lines
	ingressExpLines := make([]string, 0)
	egressExpLines := make([]string, 0)
	unprotectedLines := make([]string, 0)
	for _, ep := range sortedExposureResults {
		// ingress and egress lines per peer, internally sorted
		pIngressLines, pEgressLines, pUnprotectedLines := t.writePeerExposureAndUnprotectedLines(ep, maxPeerStrLen)
		ingressExpLines = append(ingressExpLines, pIngressLines...)
		egressExpLines = append(egressExpLines, pEgressLines...)
		unprotectedLines = append(unprotectedLines, pUnprotectedLines...)
	}
	sort.Strings(unprotectedLines)
	// results of exposure for all peers
	res := exposureAnalysisHeader
	res += writeExposureSubSection(egressExpLines, egressExpHeader)
	res += writeExposureSubSection(ingressExpLines, ingressExpHeader)
	res += writeExposureSubSection(unprotectedLines, unprotectedHeader)
	return res
}

func (t *formatText) writePeerExposureAndUnprotectedLines(ep ExposedPeer, maxPeerStrLen int) (ingressLines,
	egressLines, unprotectedLines []string) {
	// get ingress lines
	ingressLines, ingUnprotected := t.getPeerXgressExposureLines(ep.ExposedPeer().String(), ep.IngressExposure(),
		ep.IsProtectedByIngressNetpols(), true, maxPeerStrLen)
	// get egress lines
	egressLines, egUnprotected := t.getPeerXgressExposureLines(ep.ExposedPeer().String(), ep.EgressExposure(),
		ep.IsProtectedByEgressNetpols(), false, maxPeerStrLen)
	unprotectedLines = append(unprotectedLines, ingUnprotected...)
	unprotectedLines = append(unprotectedLines, egUnprotected...)
	return ingressLines, egressLines, unprotectedLines
}

// writeExposureSubSection if the list is not empty returns it as string lines with the matching given header
func writeExposureSubSection(lines []string, header string) string {
	res := ""
	if len(lines) > 0 {
		res += header
		res += strings.Join(lines, newLineChar)
		res += newLineChar
	}
	return res
}

// getPeerXgressExposureLines returns the peer's exposure data on the given direction ingress/egress arranged in output lines
func (t *formatText) getPeerXgressExposureLines(exposedPeerStr string, xgressExposure []XgressExposureData,
	isProtected, isIngress bool, maxLen int) (xgressLines, xgressUnprotectedLine []string) {
	direction := "Ingress"
	if !isIngress {
		direction = "Egress"
	}
	// if a peer is not protected, two lines are to be added to exposure analysis result:
	// 1. all conns with entire cluster (added here)
	// 2. all conns with ip-blocks (all destinations); for sure found in the ip conns map so will be added automatically
	// also unprotected line will be added
	if !isProtected {
		xgressLines = append(xgressLines, formSingleExposureConn(exposedPeerStr, entireCluster,
			common.MakeConnectionSet(true), isIngress).exposureString(isIngress, maxLen))
		xgressUnprotectedLine = append(xgressUnprotectedLine, exposedPeerStr+" is not protected on "+direction)
	} else { // protected
		for _, data := range xgressExposure {
			// for txt output append the string of the singleConnFields
			xgressLines = append(xgressLines, formExposureItemAsSingleConnFiled(exposedPeerStr, data, isIngress).exposureString(isIngress, maxLen))
		}
	}
	// append xgress ip conns to this peer from the relevant map
	ipMap := t.PeerToConnsFromIPs
	if !isIngress {
		ipMap = t.peerToConnsToIPs
	}
	if ipConns, ok := ipMap[exposedPeerStr]; ok {
		for i := range ipConns {
			connLine := ipConns[i].exposureString(isIngress, maxLen)
			xgressLines = append(xgressLines, connLine)
		}
	}
	sort.Strings(xgressLines)
	return xgressLines, xgressUnprotectedLine
}

// sortExposedPeerSlice returns sorted ExposedPeer list, and the length of the longest peer string in the slice
func sortExposedPeerSlice(exposedPeers []ExposedPeer) (ep []ExposedPeer, maxPeerStrLen int) {
	sort.Slice(exposedPeers, func(i, j int) bool {
		if exposedPeers[i].ExposedPeer().String() < exposedPeers[j].ExposedPeer().String() {
			maxPeerStrLen = max(maxPeerStrLen, len(exposedPeers[i].ExposedPeer().String()), len(exposedPeers[j].ExposedPeer().String()))
			return true
		}
		return false
	})
	return exposedPeers, maxPeerStrLen
}

// exposureString writes the current singleConnFields in the format of exposure result line
func (c singleConnFields) exposureString(isIngress bool, maxStrLen int) string {
	formatStr := fmt.Sprintf("%%-%ds \t%%s \t%%s : %%s", maxStrLen)
	if isIngress {
		return fmt.Sprintf(formatStr, c.Dst, "<=", c.Src, c.ConnString)
	}
	return fmt.Sprintf(formatStr, c.Src, "=>", c.Dst, c.ConnString)
}
