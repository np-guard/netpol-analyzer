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
)

// relevant K8s resource kinds as string values
const (
	Networkpolicy          string = "NetworkPolicy"
	Namespace              string = "Namespace"
	Pod                    string = "Pod"
	ReplicaSet             string = "ReplicaSet"
	ReplicationController  string = "ReplicationController"
	Deployment             string = "Deployment"
	Statefulset            string = "StatefulSet"
	Daemonset              string = "DaemonSet"
	Job                    string = "Job"
	CronJob                string = "CronJob"
	List                   string = "List"
	NamespaceList          string = "NamespaceList"
	NetworkpolicyList      string = "NetworkPolicyList"
	PodList                string = "PodList"
	Service                string = "Service"
	Route                  string = "Route"
	Ingress                string = "Ingress"
	AdminNetworkPolicy     string = "AdminNetworkPolicy"
	AdminNetworkPolicyList string = "AdminNetworkPolicyList"
)

// K8sObject holds a an object kind and a pointer of the relevant object
type K8sObject struct {
	Kind string
	// namespace object
	Namespace *v1.Namespace

	// netpol objects
	Networkpolicy      *netv1.NetworkPolicy
	AdminNetworkPolicy *apisv1a.AdminNetworkPolicy

	// pod object
	Pod *v1.Pod

	// service object
	Service *v1.Service

	// Ingress objects
	Route   *ocroutev1.Route
	Ingress *netv1.Ingress

	// workload object
	Replicaset            *appsv1.ReplicaSet
	Deployment            *appsv1.Deployment
	Statefulset           *appsv1.StatefulSet
	ReplicationController *v1.ReplicationController
	Job                   *batchv1.Job
	CronJob               *batchv1.CronJob
	Daemonset             *appsv1.DaemonSet
}

func (k *K8sObject) getEmptyInitializedFieldObjByKind(kind string) interface{} {
	switch kind {
	case Deployment:
		k.Deployment = &appsv1.Deployment{}
		return k.Deployment
	case Daemonset:
		k.Daemonset = &appsv1.DaemonSet{}
		return k.Daemonset
	case ReplicaSet:
		k.Replicaset = &appsv1.ReplicaSet{}
		return k.Replicaset
	case Statefulset:
		k.Statefulset = &appsv1.StatefulSet{}
		return k.Statefulset
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
	case Networkpolicy:
		k.Networkpolicy = &netv1.NetworkPolicy{}
		return k.Networkpolicy
	case Namespace:
		k.Namespace = &v1.Namespace{}
		return k.Namespace
	case AdminNetworkPolicy:
		k.AdminNetworkPolicy = &apisv1a.AdminNetworkPolicy{}
		return k.AdminNetworkPolicy
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
	case Daemonset:
		if k.Daemonset.Namespace == "" {
			k.Daemonset.Namespace = metav1.NamespaceDefault
		}
	case ReplicaSet:
		if k.Replicaset.Namespace == "" {
			k.Replicaset.Namespace = metav1.NamespaceDefault
		}
	case Statefulset:
		if k.Statefulset.Namespace == "" {
			k.Statefulset.Namespace = metav1.NamespaceDefault
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
	case Networkpolicy:
		if k.Networkpolicy.Namespace == "" {
			k.Networkpolicy.Namespace = metav1.NamespaceDefault
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
	Statefulset:           true,
	Daemonset:             true,
	Job:                   true,
	CronJob:               true,
	ReplicationController: true,
}

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
		case Networkpolicy:
			if _, ok := nsMap[obj.Networkpolicy.Namespace]; ok {
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
		default:
			continue
		}
	}
	return res
}
