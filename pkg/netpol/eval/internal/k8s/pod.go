/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package k8s

import (
	"crypto/sha1" //nolint:gosec // Non-crypto use
	"encoding/hex"
	"errors"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/np-guard/netpol-analyzer/pkg/manifests/parser"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

const defaultPortsListSize = 8

// Pod encapsulates k8s Pod fields that are relevant for evaluating network policies
type Pod struct {
	Name      string
	Namespace string
	FakePod   bool // this flag is used to indicate if the pod is created from scanner objects or fake (ingress-controller)
	Labels    map[string]string
	IPs       []corev1.PodIP
	Ports     []corev1.ContainerPort
	HostIP    string
	Owner     Owner
}

// Owner encapsulates pod owner workload info
type Owner struct {
	Kind       string
	Name       string
	APIVersion string
	Variant    string // indicate the label set applied
}

// @todo need a Pod collection type along with convenience methods?
// 	if so, also consider concurrent access (or declare not goroutine safe?)

// PodFromCoreObject creates a PodRef by extracting relevant fields from the k8s Pod
func PodFromCoreObject(p *corev1.Pod) (*Pod, error) {
	if p.Status.HostIP == "" || len(p.Status.PodIPs) == 0 { // not scheduled nor assigned IP addresses - ignore
		return nil, errors.New("no worker node or IP assigned for pod: " + namespacedName(p))
	}

	pr := &Pod{
		Name:      p.Name,
		Namespace: p.Namespace,
		Labels:    make(map[string]string, len(p.Labels)),
		IPs:       make([]corev1.PodIP, len(p.Status.PodIPs)),
		Ports:     make([]corev1.ContainerPort, 0, defaultPortsListSize),
		HostIP:    p.Status.HostIP,
		Owner:     Owner{},
		FakePod:   false,
	}

	copy(pr.IPs, p.Status.PodIPs)

	for k, v := range p.Labels {
		pr.Labels[k] = v
	}

	for i := range p.Spec.Containers {
		pr.Ports = append(pr.Ports, p.Spec.Containers[i].Ports...)
	}

	for refIndex := range p.ObjectMeta.OwnerReferences {
		ownerRef := p.ObjectMeta.OwnerReferences[refIndex]
		if *ownerRef.Controller {
			if addOwner := addPodOwner(&ownerRef, pr); addOwner {
				pr.Owner.Variant = variantFromLabelsMap(p.Labels)
			}
			break
		}
	}

	return pr, nil
}

// return true if adding pod owner of a relevant kind
func addPodOwner(ownerRef *v1.OwnerReference, pod *Pod) bool {
	if ownerRef.Kind == "Node" {
		return false
	}
	pod.Owner.Name = ownerRef.Name
	pod.Owner.Kind = ownerRef.Kind
	pod.Owner.APIVersion = ownerRef.APIVersion
	return true
}

func getReplicas(r *int32) int32 {
	if r == nil {
		return 1
	}
	return *r
}

// PodsFromWorkloadObject creates a slice of one or two Pod objects by extracting relevant fields from the k8s workload
func PodsFromWorkloadObject(workload interface{}, kind string) ([]*Pod, error) { //nolint:funlen // should not break this up
	var replicas int32
	var workloadName string
	var workloadNamespace string
	var APIVersion string
	var podTemplate corev1.PodTemplateSpec
	numReplicas := 1
	switch kind {
	case parser.ReplicaSet:
		obj := workload.(*appsv1.ReplicaSet)
		replicas = getReplicas(obj.Spec.Replicas)
		workloadName = obj.Name
		workloadNamespace = obj.Namespace
		podTemplate = obj.Spec.Template
		APIVersion = obj.APIVersion
	case parser.Deployment:
		obj := workload.(*appsv1.Deployment)
		replicas = getReplicas(obj.Spec.Replicas)
		workloadName = obj.Name
		workloadNamespace = obj.Namespace
		podTemplate = obj.Spec.Template
		APIVersion = obj.APIVersion
	case parser.Statefulset:
		obj := workload.(*appsv1.StatefulSet)
		replicas = getReplicas(obj.Spec.Replicas)
		workloadName = obj.Name
		workloadNamespace = obj.Namespace
		podTemplate = obj.Spec.Template
		APIVersion = obj.APIVersion
	case parser.Daemonset:
		obj := workload.(*appsv1.DaemonSet)
		replicas = 1
		workloadName = obj.Name
		workloadNamespace = obj.Namespace
		podTemplate = obj.Spec.Template
		APIVersion = obj.APIVersion
	case parser.ReplicationController:
		obj := workload.(*corev1.ReplicationController)
		replicas = getReplicas(obj.Spec.Replicas)
		workloadName = obj.Name
		workloadNamespace = obj.Namespace
		podTemplate = *obj.Spec.Template
		APIVersion = obj.APIVersion
	case parser.CronJob:
		obj := workload.(*batchv1.CronJob)
		replicas = 1
		workloadName = obj.Name
		workloadNamespace = obj.Namespace
		podTemplate = obj.Spec.JobTemplate.Spec.Template
		APIVersion = obj.APIVersion
	case parser.Job:
		obj := workload.(*batchv1.Job)
		replicas = getReplicas(obj.Spec.Parallelism)
		workloadName = obj.Name
		workloadNamespace = obj.Namespace
		podTemplate = obj.Spec.Template
		APIVersion = obj.APIVersion

	default:
		return nil, fmt.Errorf("unexpected workload kind: %s", kind)
	}

	// allow at most 2 peers from each equivalence group
	if replicas > 1 {
		numReplicas = 2
	}

	res := make([]*Pod, numReplicas)
	for index := 1; index <= numReplicas; index++ {
		pod := &Pod{}
		pod.Name = fmt.Sprintf("%s-%d", workloadName, index)
		pod.Namespace = workloadNamespace
		pod.Labels = make(map[string]string, len(podTemplate.Labels))
		pod.IPs = make([]corev1.PodIP, 0)
		pod.Ports = make([]corev1.ContainerPort, 0, defaultPortsListSize)
		pod.HostIP = getFakePodIP()
		pod.Owner = Owner{Name: workloadName, Kind: kind, APIVersion: APIVersion}
		pod.FakePod = false
		for k, v := range podTemplate.Labels {
			pod.Labels[k] = v
		}
		for i := range podTemplate.Spec.Containers {
			pod.Ports = append(pod.Ports, podTemplate.Spec.Containers[i].Ports...)
		}
		pod.Owner.Variant = variantFromLabelsMap(podTemplate.Labels)
		res[index-1] = pod
	}
	return res, nil
}

// canonical Pod name
func namespacedName(pod *corev1.Pod) string {
	return types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}.String()
}

func variantFromLabelsMap(labels map[string]string) string {
	return hex.EncodeToString(sha1.New().Sum([]byte(fmt.Sprintf("%v", labels)))) //nolint:gosec // Non-crypto use
}

func getFakePodIP() string {
	return parser.IPv4LoopbackAddr
}

// PodExposedTCPConnections returns TCP connections exposed by a pod
func (pod *Pod) PodExposedTCPConnections() *common.ConnectionSet {
	res := common.MakeConnectionSet(false)
	for _, cPort := range pod.Ports {
		protocol := corev1.ProtocolTCP
		if cPort.Protocol == "" || protocol == corev1.ProtocolTCP {
			ports := common.MakePortSet(false)
			ports.AddPortRange(int64(cPort.ContainerPort), int64(cPort.ContainerPort))
			res.AddConnection(protocol, ports)
		}
	}
	return res
}

const noPort = -1

// ConvertPodNamedPort returns the ContainerPort's protocol and number that matches the named port
// if there is no match, returns empty string for protocol and -1 for number
func (pod *Pod) ConvertPodNamedPort(namedPort string) (protocol corev1.Protocol, portNum int32) {
	for _, containerPort := range pod.Ports {
		if namedPort == containerPort.Name {
			return containerPort.Protocol, containerPort.ContainerPort
		}
	}
	return "", noPort
}
