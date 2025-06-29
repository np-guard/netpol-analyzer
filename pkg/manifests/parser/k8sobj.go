/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package parser

import (
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	apisv1a "sigs.k8s.io/network-policy-api/apis/v1alpha1"

	ocroutev1 "github.com/openshift/api/route/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	mnpv1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta2"
	nadv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	udnv1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/userdefinednetwork/v1"
	kubevirt "kubevirt.io/api/core/v1"
)

// relevant K8s resource kinds as string values
const (
	NetworkPolicy                   string = "NetworkPolicy"
	Namespace                       string = "Namespace"
	Pod                             string = "Pod"
	ReplicaSet                      string = "ReplicaSet"
	ReplicationController           string = "ReplicationController"
	Deployment                      string = "Deployment"
	StatefulSet                     string = "StatefulSet"
	DaemonSet                       string = "DaemonSet"
	Job                             string = "Job"
	CronJob                         string = "CronJob"
	List                            string = "List"
	NamespaceList                   string = "NamespaceList"
	NetworkPolicyList               string = "NetworkPolicyList"
	PodList                         string = "PodList"
	Service                         string = "Service"
	Route                           string = "Route"
	Ingress                         string = "Ingress"
	AdminNetworkPolicy              string = "AdminNetworkPolicy"
	AdminNetworkPolicyList          string = "AdminNetworkPolicyList"
	BaselineAdminNetworkPolicy      string = "BaselineAdminNetworkPolicy"
	BaselineAdminNetworkPolicyList  string = "BaselineAdminNetworkPolicyList" // a list with max 1 object according to apis/v1alpha
	UserDefinedNetwork              string = "UserDefinedNetwork"
	UserDefinedNetworkList          string = "UserDefinedNetworkList"
	ClusterUserDefinedNetwork       string = "ClusterUserDefinedNetwork"
	ClusterUserDefinedNetworkList   string = "ClusterUserDefinedNetworkList"
	VirtualMachine                  string = "VirtualMachine"
	VirtualMachineList              string = "VirtualMachineList"
	NetworkAttachmentDefinition     string = "NetworkAttachmentDefinition"
	NetworkAttachmentDefinitionList string = "NetworkAttachmentDefinitionList"
	MultiNetworkPolicy              string = "MultiNetworkPolicy"
	MultiNetworkPolicyList          string = "MultiNetworkPolicyList"
)

// K8sObject holds a an object kind and a pointer of the relevant object
type K8sObject struct {
	Kind string
	// namespace object
	Namespace *v1.Namespace

	// netpol objects
	NetworkPolicy              *netv1.NetworkPolicy
	AdminNetworkPolicy         *apisv1a.AdminNetworkPolicy
	BaselineAdminNetworkPolicy *apisv1a.BaselineAdminNetworkPolicy

	// pod object
	Pod *v1.Pod

	// service object
	Service *v1.Service

	// Ingress objects
	Route   *ocroutev1.Route
	Ingress *netv1.Ingress

	// workload object
	ReplicaSet            *appsv1.ReplicaSet
	Deployment            *appsv1.Deployment
	StatefulSet           *appsv1.StatefulSet
	ReplicationController *v1.ReplicationController
	Job                   *batchv1.Job
	CronJob               *batchv1.CronJob
	DaemonSet             *appsv1.DaemonSet

	// ovn-k8s objects
	UserDefinedNetwork        *udnv1.UserDefinedNetwork
	ClusterUserDefinedNetwork *udnv1.ClusterUserDefinedNetwork
	VirtualMachine            *kubevirt.VirtualMachine

	NetworkAttachmentDefinition *nadv1.NetworkAttachmentDefinition
	MultiNetworkPolicy          *mnpv1.MultiNetworkPolicy
}

//gocyclo:ignore
func (k *K8sObject) getEmptyInitializedFieldObjByKind(kind string) interface{} { //nolint:funlen // should not break this up
	switch kind {
	case Deployment:
		k.Deployment = &appsv1.Deployment{}
		return k.Deployment
	case DaemonSet:
		k.DaemonSet = &appsv1.DaemonSet{}
		return k.DaemonSet
	case ReplicaSet:
		k.ReplicaSet = &appsv1.ReplicaSet{}
		return k.ReplicaSet
	case StatefulSet:
		k.StatefulSet = &appsv1.StatefulSet{}
		return k.StatefulSet
	case ReplicationController:
		k.ReplicationController = &v1.ReplicationController{}
		return k.ReplicationController
	case Job:
		k.Job = &batchv1.Job{}
		return k.Job
	case CronJob:
		k.CronJob = &batchv1.CronJob{}
		return k.CronJob
	case Route:
		k.Route = &ocroutev1.Route{}
		return k.Route
	case Ingress:
		k.Ingress = &netv1.Ingress{}
		return k.Ingress
	case Service:
		k.Service = &v1.Service{}
		return k.Service
	case Pod:
		k.Pod = &v1.Pod{}
		return k.Pod
	case NetworkPolicy:
		k.NetworkPolicy = &netv1.NetworkPolicy{}
		return k.NetworkPolicy
	case Namespace:
		k.Namespace = &v1.Namespace{}
		return k.Namespace
	case AdminNetworkPolicy:
		k.AdminNetworkPolicy = &apisv1a.AdminNetworkPolicy{}
		return k.AdminNetworkPolicy
	case BaselineAdminNetworkPolicy:
		k.BaselineAdminNetworkPolicy = &apisv1a.BaselineAdminNetworkPolicy{}
		return k.BaselineAdminNetworkPolicy
	case UserDefinedNetwork:
		k.UserDefinedNetwork = &udnv1.UserDefinedNetwork{}
		return k.UserDefinedNetwork
	case ClusterUserDefinedNetwork:
		k.ClusterUserDefinedNetwork = &udnv1.ClusterUserDefinedNetwork{}
		return k.ClusterUserDefinedNetwork
	case NetworkAttachmentDefinition:
		k.NetworkAttachmentDefinition = &nadv1.NetworkAttachmentDefinition{}
		return k.NetworkAttachmentDefinition
	case VirtualMachine:
		k.VirtualMachine = &kubevirt.VirtualMachine{}
		return k.VirtualMachine
	case MultiNetworkPolicy:
		k.MultiNetworkPolicy = &mnpv1.MultiNetworkPolicy{}
		return k.MultiNetworkPolicy
	}
	return nil
}

//gocyclo:ignore
func (k *K8sObject) initDefaultNamespace() {
	switch k.Kind {
	case Deployment:
		if k.Deployment.Namespace == "" {
			k.Deployment.Namespace = metav1.NamespaceDefault
		}
	case DaemonSet:
		if k.DaemonSet.Namespace == "" {
			k.DaemonSet.Namespace = metav1.NamespaceDefault
		}
	case ReplicaSet:
		if k.ReplicaSet.Namespace == "" {
			k.ReplicaSet.Namespace = metav1.NamespaceDefault
		}
	case StatefulSet:
		if k.StatefulSet.Namespace == "" {
			k.StatefulSet.Namespace = metav1.NamespaceDefault
		}
	case ReplicationController:
		if k.ReplicationController.Namespace == "" {
			k.ReplicationController.Namespace = metav1.NamespaceDefault
		}
	case Job:
		if k.Job.Namespace == "" {
			k.Job.Namespace = metav1.NamespaceDefault
		}
	case CronJob:
		if k.CronJob.Namespace == "" {
			k.CronJob.Namespace = metav1.NamespaceDefault
		}
	case Route:
		if k.Route.Namespace == "" {
			k.Route.Namespace = metav1.NamespaceDefault
		}
	case Ingress:
		if k.Ingress.Namespace == "" {
			k.Ingress.Namespace = metav1.NamespaceDefault
		}
	case Service:
		if k.Service.Namespace == "" {
			k.Service.Namespace = metav1.NamespaceDefault
		}
	case Pod:
		if k.Pod.Namespace == "" {
			k.Pod.Namespace = metav1.NamespaceDefault
		}
		checkAndUpdatePodStatusIPsFields(k.Pod)
	case NetworkPolicy:
		if k.NetworkPolicy.Namespace == "" {
			k.NetworkPolicy.Namespace = metav1.NamespaceDefault
		}
	case UserDefinedNetwork:
		if k.UserDefinedNetwork.Namespace == "" {
			k.UserDefinedNetwork.Namespace = metav1.NamespaceDefault
		}
	case NetworkAttachmentDefinition:
		if k.NetworkAttachmentDefinition.Namespace == "" {
			k.NetworkAttachmentDefinition.Namespace = metav1.NamespaceDefault
		}
	case VirtualMachine:
		if k.VirtualMachine.Namespace == "" {
			k.VirtualMachine.Namespace = metav1.NamespaceDefault
		}
	case MultiNetworkPolicy:
		if k.MultiNetworkPolicy.Namespace == "" {
			k.MultiNetworkPolicy.Namespace = metav1.NamespaceDefault
		}
	}
}

// IPv4LoopbackAddr is used as fake IP in the absence of Pod.Status.HostIP or Pod.Status.PodIPs
const IPv4LoopbackAddr = "127.0.0.1"

// checkAndUpdatePodStatusIPsFields adds fake IP to pod.Status.HostIP or pod.Status.PodIPs if missing
func checkAndUpdatePodStatusIPsFields(rc *v1.Pod) {
	if rc.Status.HostIP == "" {
		rc.Status.HostIP = IPv4LoopbackAddr
	}
	if len(rc.Status.PodIPs) == 0 {
		rc.Status.PodIPs = []v1.PodIP{{IP: IPv4LoopbackAddr}}
	}
}

var workloadKinds = map[string]bool{
	Pod:                   true,
	ReplicaSet:            true,
	Deployment:            true,
	StatefulSet:           true,
	DaemonSet:             true,
	Job:                   true,
	CronJob:               true,
	ReplicationController: true,
	VirtualMachine:        true,
}

var policyKinds = map[string]bool{
	NetworkPolicy:              true,
	AdminNetworkPolicy:         true,
	BaselineAdminNetworkPolicy: true,
	MultiNetworkPolicy:         true,
}

//gocyclo:ignore
func FilterObjectsList(allObjects []K8sObject, podNames []types.NamespacedName) []K8sObject {
	podNamesMap := make(map[string]bool, 0)
	nsMap := make(map[string]bool, 0)
	for i := range podNames {
		podNamesMap[podNames[i].String()] = true
		nsMap[podNames[i].Namespace] = true
	}
	res := make([]K8sObject, 0)
	for i := range allObjects {
		obj := allObjects[i]
		switch obj.Kind {
		case Namespace:
			if _, ok := nsMap[obj.Namespace.Name]; ok {
				res = append(res, obj)
			}
		case NetworkPolicy:
			if _, ok := nsMap[obj.NetworkPolicy.Namespace]; ok {
				res = append(res, obj)
			}
		case Pod:
			if _, ok := podNamesMap[types.NamespacedName{Name: obj.Pod.Name, Namespace: obj.Pod.Namespace}.String()]; ok {
				res = append(res, obj)
			}
		case Service:
			if _, ok := nsMap[obj.Service.Namespace]; ok {
				res = append(res, obj)
			}
		case Route:
			if _, ok := nsMap[obj.Route.Namespace]; ok {
				res = append(res, obj)
			}
		case Ingress:
			if _, ok := nsMap[obj.Ingress.Namespace]; ok {
				res = append(res, obj)
			}
		case UserDefinedNetwork:
			if _, ok := nsMap[obj.UserDefinedNetwork.Namespace]; ok {
				res = append(res, obj)
			}
		case ClusterUserDefinedNetwork:
			res = append(res, obj)
		case NetworkAttachmentDefinition:
			if _, ok := nsMap[obj.NetworkAttachmentDefinition.Namespace]; ok {
				res = append(res, obj)
			}
		case VirtualMachine:
			if _, ok := nsMap[obj.VirtualMachine.Namespace]; ok {
				res = append(res, obj)
			}
		case AdminNetworkPolicy:
			res = append(res, obj)
		case BaselineAdminNetworkPolicy:
			res = append(res, obj)
		case MultiNetworkPolicy:
			if _, ok := nsMap[obj.MultiNetworkPolicy.Namespace]; ok {
				res = append(res, obj)
			}
		default:
			continue
		}
	}
	return res
}
