package list

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/scan"
)

// ListConnectionsFromDir returns connections map from dir path resources
func ListConnectionsFromDir(dirPath string) (string, error) {
	pe := eval.NewPolicyEngine()
	// get all resources from dir
	objectsList, err := scan.FilesToObjectsList(dirPath)
	if err != nil {
		return "", err
	}
	for _, obj := range objectsList {
		if obj.Kind == scan.Pod {
			err = pe.UpsertObject(obj.Pod)
		} else if obj.Kind == scan.Namespace {
			err = pe.UpsertObject(obj.Namespace)
		} else if obj.Kind == scan.Networkpolicy {
			err = pe.UpsertObject(obj.Networkpolicy)
		}
		if err != nil {
			return "", err
		}
	}

	return getConnectionsMapOutput(pe)
}

// ListConnectionsFromK8sCluster returns connections map from k8s cluster resources
func ListConnectionsFromK8sCluster(clientset *kubernetes.Clientset) (string, error) {
	pe := eval.NewPolicyEngine()

	// get all resources from k8s cluster

	// get all namespaces
	nsList, apierr := clientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
	if apierr != nil {
		return "", apierr
	}
	for i := range nsList.Items {
		ns := &nsList.Items[i]
		if err := pe.UpsertObject(ns); err != nil {
			return "", err
		}
	}

	// get all pods
	podList, apierr := clientset.CoreV1().Pods(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{})
	if apierr != nil {
		return "", apierr
	}
	for i := range podList.Items {
		if err := pe.UpsertObject(&podList.Items[i]); err != nil {
			return "", err
		}
	}

	// get all netpols
	npList, apierr := clientset.NetworkingV1().NetworkPolicies(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{})
	if apierr != nil {
		return "", apierr
	}
	for i := range npList.Items {
		if err := pe.UpsertObject(&npList.Items[i]); err != nil {
			return "", err
		}
	}

	return getConnectionsMapOutput(pe)
}

// getConnectionsMapOutput returns connections map from PolicyEngine object
func getConnectionsMapOutput(pe *eval.PolicyEngine) (string, error) {
	res := ""
	// get connections map output
	// TODO: consider workloads as well
	podsMap := pe.GetPodsMap()
	for srcPod := range podsMap {
		for dstPod := range podsMap {
			allowedConnections, err := pe.AllAllowedConnections(srcPod, dstPod)
			if err == nil {
				res += fmt.Sprintf("%v => %v : %v\n", srcPod, dstPod, allowedConnections.String())
			} else {
				return "", err
			}
		}
	}
	return res, nil
}
