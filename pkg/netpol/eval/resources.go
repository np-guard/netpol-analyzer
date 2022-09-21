package eval

import (
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval/internal/k8s"
)

var pods = []*k8s.Pod{}
var namespaces = []*k8s.Namespace{}
var namspacesMap = map[string]*k8s.Namespace{}     // map from ns name to ns object
var podsMap = map[string]*k8s.Pod{}                // map from pod name to pod object
var netpolsMap = map[string][]*k8s.NetworkPolicy{} // map from netpol's namespace to netpol object

// getPod: returns a Pod object corresponding to the input pod name
func getPod(p string) *k8s.Pod {
	if pod, ok := podsMap[p]; ok {
		return pod
	}
	return nil
}

// SetResources: updates the set of all relevant k8s resources
func SetResources(npList []*netv1.NetworkPolicy, podList []*corev1.Pod, nsList []*corev1.Namespace) error {
	for i := range npList {
		netpolNamespace := npList[i].ObjectMeta.Namespace
		if netpolNamespace == "" {
			netpolNamespace = defaultNamespace
			npList[i].ObjectMeta.Namespace = defaultNamespace
		}
		if _, ok := netpolsMap[netpolNamespace]; !ok {
			netpolsMap[netpolNamespace] = []*k8s.NetworkPolicy{(*k8s.NetworkPolicy)(npList[i])}
		} else {
			netpolsMap[netpolNamespace] = append(netpolsMap[netpolNamespace], (*k8s.NetworkPolicy)(npList[i]))
		}
	}
	for i := range podList {
		podObj, err := k8s.PodFromCoreObject(podList[i])
		if err != nil {
			return err
		}
		pods = append(pods, podObj)
		podStr := types.NamespacedName{Namespace: podObj.Namespace, Name: podObj.Name}
		podsMap[podStr.String()] = podObj
	}

	for i := range nsList {
		nsObj, err := k8s.NamespaceFromCoreObject(nsList[i])
		if err != nil {
			return err
		}
		namespaces = append(namespaces, nsObj)
		namspacesMap[nsObj.Name] = nsObj
	}

	return nil
}

// ClearResources: deletes all current k8s resources
func ClearResources() {
	pods = []*k8s.Pod{}
	namespaces = []*k8s.Namespace{}
	namspacesMap = map[string]*k8s.Namespace{} // map from ns name to ns object
	podsMap = map[string]*k8s.Pod{}            // map from pod name to pod object
	netpolsMap = map[string][]*k8s.NetworkPolicy{}
}

func GetReferencedIPBlocks() {

}
