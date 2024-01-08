package exposureanalysis

import (
	"fmt"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

type xgressExposure struct {
	protected bool
	// entire namespace is exposed
	namespacesExposed []string // TODO: add conns which the namespace exposed on (replace with map[string]common.Connection)

	// podsExposed (TODO: to adds pods exposed in next PRs)
}

type exposureInfo struct {
	ingressExposure xgressExposure
	egressExposure  xgressExposure
}

// in next PRs - return the potential conns (to append to output results)
func GetPotentialAllowedConnections(pe *eval.PolicyEngine, peers []eval.Peer) error {
	res := map[eval.Peer]exposureInfo{} // map from peer to its exposure info
	for _, peer := range peers {
		if peer.IsPeerIPType() {
			continue
		}
		// get potentially ingress exposed
		ingressEx := xgressExposure{}
		captured, namespaces, err := pe.GetPeerPotentiallyAllowedConns(peer, true)
		if err != nil {
			return err
		}
		if !captured {
			ingressEx.protected = false
			ingressEx.namespacesExposed = nil
		} else {
			ingressEx.protected = true
			ingressEx.namespacesExposed = namespaces
		}

		// egress potentially
		egressEx := xgressExposure{}
		captured, namespaces, err = pe.GetPeerPotentiallyAllowedConns(peer, false)
		if err != nil {
			return err
		}
		// TODO : avoid code dup
		if !captured {
			egressEx.protected = false
			egressEx.namespacesExposed = nil
		} else {
			egressEx.protected = true
			egressEx.namespacesExposed = namespaces
		}

		res[peer] = exposureInfo{ingressExposure: ingressEx, egressExposure: egressEx}
	}

	printRes(res)
	return nil
}

func printRes(exposureAnalysisRes map[eval.Peer]exposureInfo) {
	fmt.Printf("\n EXPOSURE ANALYSIS: \n")
	for peer, exposureDetails := range exposureAnalysisRes {
		if !exposureDetails.ingressExposure.protected && !exposureDetails.egressExposure.protected {
			fmt.Printf("%q  : is not protected in the cluster\n", peer.String())
			continue
		}
		if !exposureDetails.ingressExposure.protected {
			fmt.Printf("%q : is not protected on Ingress\n", peer.String())
		}
		if !exposureDetails.egressExposure.protected {
			fmt.Printf("%q : is not protected on Egress\n", peer.String())
		}
		if len(exposureDetails.ingressExposure.namespacesExposed) > 0 {
			fmt.Printf("%q : is exposed on Ingress from:\n", peer.String())
			for i := range exposureDetails.ingressExposure.namespacesExposed {
				if exposureDetails.ingressExposure.namespacesExposed[i] == common.AllNamespaces {
					fmt.Printf("* %s\n", common.AllNamespaces)
				} else {
					fmt.Printf("* any namespace with selector/s: %q \n", exposureDetails.ingressExposure.namespacesExposed[i])
				}
			}
		}
		if len(exposureDetails.egressExposure.namespacesExposed) > 0 {
			fmt.Printf("%q : is exposed on Egress to:\n", peer.String())
			for i := range exposureDetails.egressExposure.namespacesExposed {
				if exposureDetails.egressExposure.namespacesExposed[i] == common.AllNamespaces {
					fmt.Printf("* %s\n", common.AllNamespaces)
				} else {
					fmt.Printf("* any namespace with selector/s : %q \n", exposureDetails.egressExposure.namespacesExposed[i])
				}
			}
		}
	}
	fmt.Printf("\n")
}
