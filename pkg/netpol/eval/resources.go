package eval

import (
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval/internal/k8s"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
)

//var netpols = []*k8s.NetworkPolicy{}
var pods = []*k8s.Pod{}
var namespaces = []*k8s.Namespace{}
var namspacesMap = map[string]*k8s.Namespace{}     // map from ns name to ns object
var podsMap = map[string]*k8s.Pod{}                //map from pod name to pod object
var netpolsMap = map[string][]*k8s.NetworkPolicy{} // map from netpol's namespace to netpol object

func GetPod(p string) *k8s.Pod {
	if pod, ok := podsMap[p]; ok {
		return pod
	}
	return nil
}

func SetResourcesFromDir(path string, netpolLimit ...int) error {
	objectsList, err := FilesToObjectsList(path)
	if err != nil {
		return err
	}
	var netpols = []*netv1.NetworkPolicy{}
	var pods = []*corev1.Pod{}
	var ns = []*corev1.Namespace{}
	for _, obj := range objectsList {
		if obj.kind == "Pod" {
			pods = append(pods, obj.pod)
		} else if obj.kind == "Namespace" {
			ns = append(ns, obj.namespace)
		} else if obj.kind == "NetworkPolicy" {
			netpols = append(netpols, obj.networkpolicy)
		}
	}
	if len(netpolLimit) > 0 {
		netpols = netpols[:netpolLimit[0]]
	}
	return SetResources(netpols, pods, ns)

}

func SetResources(npList []*netv1.NetworkPolicy, podList []*corev1.Pod, nsList []*corev1.Namespace) error {
	//TODO: bug here: apending only the last element?
	for i := range npList {
		//netpols = append(netpols, (*k8s.NetworkPolicy)(np))
		netpolNamespace := npList[i].ObjectMeta.Namespace
		if len(netpolNamespace) == 0 {
			netpolNamespace = "default"
			npList[i].ObjectMeta.Namespace = "default"
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

func ClearResources() {
	//netpols = []*k8s.NetworkPolicy{}
	pods = []*k8s.Pod{}
	namespaces = []*k8s.Namespace{}
	namspacesMap = map[string]*k8s.Namespace{} // map from ns name to ns object
	podsMap = map[string]*k8s.Pod{}            //map from pod name to pod object
	netpolsMap = map[string][]*k8s.NetworkPolicy{}
}

func GetReferencedIpBlocks() {

}
