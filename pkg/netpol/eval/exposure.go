package eval

import (
	netv1 "k8s.io/api/networking/v1"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval/internal/k8s"
)

func (pe *PolicyEngine) GetPeerPotentiallyAllowedConns(checkedPeer Peer, isIngress bool) (captured bool,
	netpolsExposed []string, err error) {
	checkedPodPeer, err := pe.convertWorkloadPeerToPodPeer(checkedPeer)
	if err != nil {
		return false, nil, err
	}

	policyType := netv1.PolicyTypeIngress
	if !isIngress {
		policyType = netv1.PolicyTypeEgress
	}

	netpols, err := pe.getPoliciesSelectingPod(checkedPodPeer.GetPeerPod(), policyType)
	if err != nil {
		return false, nil, err
	}

	if len(netpols) == 0 {
		return false, nil, nil
	}
	for _, policy := range netpols {
		netpolsExposed = append(netpolsExposed, getPotentiallyExposedNamespaces(policy, isIngress)...)
	}

	return true, netpolsExposed, nil
}

func getPotentiallyExposedNamespaces(policy *k8s.NetworkPolicy, isIngress bool) []string {
	if isIngress {
		return policy.GetPotentialExposedNamespacesForIngress()
	}
	return policy.GetPotentialExposedNamespacesForEgress()
}
