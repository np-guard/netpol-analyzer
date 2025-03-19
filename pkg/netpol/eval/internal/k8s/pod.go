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
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/np-guard/netpol-analyzer/pkg/manifests/parser"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

const defaultPortsListSize = 8

type PodExposureInfo struct {
	// 	IsProtected indicates if the pod is selected by any network-policy or not
	IsProtected bool
	// ClusterWideConnection contains the maximal connection-set for which the pod is exposed to all namespaces by network policies
	ClusterWideConnection *common.ConnectionSet
}

func initiatePodExposure() PodExposureInfo {
	return PodExposureInfo{
		IsProtected:           false,
		ClusterWideConnection: common.MakeConnectionSet(false),
	}
}

// Pod encapsulates k8s Pod fields that are relevant for evaluating network policies
type Pod struct {
	Name      string
	Namespace string
	FakePod   bool // this flag is used to indicate if the pod is created from scanner objects or fake (ingress-controller/ representative pod)
	Labels    map[string]string
	IPs       []corev1.PodIP
	Ports     []corev1.ContainerPort
	HostIP    string
	Owner     Owner

	// The fields below are relevant to real pods when exposure analysis is active:

	// IngressExposureData contains:
	// - whether the pod is protected by any network-policy on ingress direction or not;
	// - the maximal connection-set for which the pod is exposed to all namespaces  in the cluster by
	// network policies on ingress direction
	IngressExposureData PodExposureInfo
	// EgressExposureData contains:
	// - whether the pod is protected by any network-policy on egress direction or not;
	// - the maximal connection-set for which the pod is exposed to all namespaces in the cluster by
	// network policies on egress direction
	EgressExposureData PodExposureInfo
	// RepresentativePodLabelSelector contains reference to the podSelector of the policy-rule which the representative peer was inferred from
	// used only with representative Pods
	// RepresentativePodLabelSelector might be nil/ empty selector / a specific non-empty selector

	// The fields below are relevant only to representative pod:
	RepresentativePodLabelSelector *v1.LabelSelector
	// RepresentativeNsLabelSelector points to the namespaceSelector of the policy rule which this representative pod was inferred from
	// used only with representative peers (exposure-analysis)
	// RepresentativeNsLabelSelector might represent an empty selector / a specific non-empty selector (will not be nil)
	// nil namespaceSelector in a policy-rule will be converted to the namespace name label when creating the representative pod.
	RepresentativeNsLabelSelector *v1.LabelSelector

	// possible combinations of RepresentativePodLabelSelector and RepresentativeNsLabelSelector:
	// - both are specific non-empty selectors : implies for any pod with labels matching RepresentativePodLabelSelector;
	// in a any namespace with labels matching RepresentativeNsLabelSelector.
	// - RepresentativePodLabelSelector is nil + RepresentativeNsLabelSelector is a specific non-empty selector : implies
	// for all pods in a namespace with labels matching RepresentativeNsLabelSelector.
	// - RepresentativePodLabelSelector is empty + RepresentativeNsLabelSelector is a specific non-empty selector : also
	// implies for all pods in a namespace with labels matching RepresentativeNsLabelSelector.
	// - RepresentativePodLabelSelector a specific non-empty selector + RepresentativeNsLabelSelector is an empty selector :
	// implies for any pod with labels matching RepresentativePodLabelSelector in any namespace in the cluster.
	// both might not be nil / empty at same time
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
		Name:                p.Name,
		Namespace:           p.Namespace,
		Labels:              make(map[string]string, len(p.Labels)),
		IPs:                 make([]corev1.PodIP, len(p.Status.PodIPs)),
		Ports:               make([]corev1.ContainerPort, 0, defaultPortsListSize),
		HostIP:              p.Status.HostIP,
		Owner:               Owner{},
		FakePod:             false,
		IngressExposureData: initiatePodExposure(),
		EgressExposureData:  initiatePodExposure(),
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
		if ownerRef.Controller != nil && *ownerRef.Controller {
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
	case parser.StatefulSet:
		obj := workload.(*appsv1.StatefulSet)
		replicas = getReplicas(obj.Spec.Replicas)
		workloadName = obj.Name
		workloadNamespace = obj.Namespace
		podTemplate = obj.Spec.Template
		APIVersion = obj.APIVersion
	case parser.DaemonSet:
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
		pod.IngressExposureData = initiatePodExposure()
		pod.EgressExposureData = initiatePodExposure()
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

// variantFromLabelsMap returns a unique hash key from given labels map
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
			ports.AddPortRange(int64(cPort.ContainerPort), int64(cPort.ContainerPort), true, "", "", true)
			res.AddConnection(protocol, ports)
		}
	}
	return res
}

// ConvertPodNamedPort returns the ContainerPort's protocol and number that matches the named port
// if there is no match, returns empty string for protocol and -1 for number
// namedPort is unique within the pod
func (pod *Pod) ConvertPodNamedPort(namedPort string) (protocol string, portNum int32) {
	for _, containerPort := range pod.Ports {
		if namedPort == containerPort.Name { // found
			if containerPort.Protocol == "" {
				// found the named port with unspecified protocol this means "TCP" protocol (default)
				return string(corev1.ProtocolTCP), containerPort.ContainerPort
			}
			return string(containerPort.Protocol), containerPort.ContainerPort
		}
	}
	return "", common.NoPort
}

// updatePodXgressExposureToEntireClusterData updates the pods' fields which are related to entire class exposure on ingress/egress
func (pod *Pod) UpdatePodXgressExposureToEntireClusterData(ruleConns *common.ConnectionSet, isIngress bool) {
	if isIngress {
		// for a dst pod check if the given ruleConns contains namedPorts; if yes replace them with pod's
		// matching port number
		convertedConns := pod.checkAndConvertNamedPortsInConnection(ruleConns)
		if convertedConns != nil {
			pod.IngressExposureData.ClusterWideConnection.Union(convertedConns, false)
		} else {
			pod.IngressExposureData.ClusterWideConnection.Union(ruleConns, false)
		}
	} else {
		pod.EgressExposureData.ClusterWideConnection.Union(ruleConns, false)
	}
}

// checkAndConvertNamedPortsInConnection returns the copy of the given connectionSet where named ports are converted;
// returns nil if the given connectionSet has no named ports
func (pod *Pod) checkAndConvertNamedPortsInConnection(conns *common.ConnectionSet) *common.ConnectionSet {
	connNamedPorts := conns.GetNamedPorts()
	if len(connNamedPorts) == 0 {
		return nil
	} // else - found named ports
	connsCopy := conns.Copy() // copying the connectionSet; in order to replace
	// the named ports with pod's port numbers if possible
	for protocol, namedPorts := range connNamedPorts {
		for namedPort, implyingRules := range namedPorts {
			// get the matching protocol and port-number from the pod-configuration
			podProtocol, portNum := pod.ConvertPodNamedPort(namedPort)
			if podProtocol != "" && portNum != common.NoPort { // there is a matching containerPort in the pod configuration
				switch protocol { // the original protocol in the given conns may be either empty or not
				case "": // if empty - means inferred from an ANP rule
					// in this case we need to add the matching connection (pods' protocol+number) to the connsCopy
					newPort := common.MakePortSet(false)
					newPort.AddPort(intstr.FromInt32(portNum), implyingRules)
					connsCopy.AddConnection(corev1.Protocol(podProtocol), newPort)
					// and remove the entry with "" protocol from connsCopy
					delete(connsCopy.AllowedProtocols, protocol)
				default: // protocol is defined, replace named-port of the given protocol with its matching number
					connsCopy.ReplaceNamedPortWithMatchingPortNum(protocol, namedPort, portNum, implyingRules)
				}
			}
		}
	}
	return connsCopy
}

// UpdatePodXgressProtectedFlag updates to true the relevant ingress/egress protected flag of the pod
func (pod *Pod) UpdatePodXgressProtectedFlag(isIngress bool) {
	if isIngress {
		pod.IngressExposureData.IsProtected = true
	} else {
		pod.EgressExposureData.IsProtected = true
	}
}

// IsPodRepresentative returns if the pod is a representative pod
func (pod *Pod) IsPodRepresentative() bool {
	return pod.FakePod && pod.Name == RepresentativePodName
	// representative Pod is always generated with the RepresentativePodName (in pe.addRepresentativePod)
	// all representative pods have same name, since the name is used only here (to indicate if it is a representative)
	// not used for storing/ comparing with other pods
}
