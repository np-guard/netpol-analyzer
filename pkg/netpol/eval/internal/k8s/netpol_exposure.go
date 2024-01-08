package k8s

import (
	netv1 "k8s.io/api/networking/v1"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// checks rules with only namespaceSelector
func (np *NetworkPolicy) GetPotentialExposedNamespacesForIngress() []string {
	// nsToConns := make(map[string]*common.ConnectionSet, 0)
	namespacesExposed := make([]string, 0)
	for _, rule := range np.Spec.Ingress {
		ruleFrom := rule.From
		// rulePorts := rule.Ports   // TODO: add on what ports (conns) the namespace is exposed
		namespacesExposed = append(namespacesExposed, np.getNamespacesSelectedByRule(ruleFrom)...)
	}

	return namespacesExposed
}

func (np *NetworkPolicy) GetPotentialExposedNamespacesForEgress() []string {
	namespacesExposed := make([]string, 0)
	for _, rule := range np.Spec.Egress {
		ruleTo := rule.To
		namespacesExposed = append(namespacesExposed, np.getNamespacesSelectedByRule(ruleTo)...)
	}

	return namespacesExposed
}

func (np *NetworkPolicy) getNamespacesSelectedByRule(rulePeers []netv1.NetworkPolicyPeer) []string {
	res := make([]string, 0)
	if len(rulePeers) == 0 { // allow all ingress
		res = append(res, common.AllNamespaces)
		return res
	}
	for i := range rulePeers { // assumes all rules are good (since connlist analysis already returned errors)
		if rulePeers[i].IPBlock != nil {
			continue
		}
		if rulePeers[i].PodSelector != nil {
			continue
		}
		// rule contains only namespaceSelector
		selector, _ := np.parseNetpolLabelSelector(rulePeers[i].NamespaceSelector)
		selectorStr := selector.String()
		if selectorStr == "" {
			res = append(res, common.AllNamespaces)
		} else {
			res = append(res, selector.String())
		}
	}

	return res
}
