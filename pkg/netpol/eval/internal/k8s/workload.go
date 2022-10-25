// Copyright 2022
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package k8s

import (
	"crypto/sha1" //nolint:gosec
	"encoding/hex"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

const (
	separator = "/"
)

// Workload encapsulats k8s Workload fields that are relevant for evaluating network policies
// k8s Workload is a Pod owner  (e.g., ReplicaSet, Deployment, StatefulSet, Job)
// can be created (1) from a pod (based on owner reference data) or (2) from a pod-creating resource
// not all pods have an owner
// TODO: check - can a pod deviate from its owner's ports/named ports?
type Workload struct {
	Name           string
	Namespace      string
	Labels         map[string]string
	Ports          []corev1.ContainerPort
	Kind           string
	Variant        string // relevant for workloads created from a pod (ownership info)
	CountOwnedPods int    // relevant for workloads created from a pod (ownership info)
}

// WorkloadK8sObject encapsulats various types of k8s workload resources (e.g., ReplicaSet, Deployment, StatefulSet, Job)
type WorkloadK8sObject struct {
	Kind       string
	ReplicaSet *appsv1.ReplicaSet
}

// WorkloadFromCoreObject: create a Workload object from a core object such as ReplicaSet, Deployment, StatefulSet, Job
func WorkloadFromCoreObject(obj *WorkloadK8sObject) (*Workload, error) {
	res := &Workload{}
	res.Kind = obj.Kind
	// TODO: extend to kinds other than ReplicaSet (such as Deployment)
	if obj.Kind == "ReplicaSet" {
		actualObj := obj.ReplicaSet
		if actualObj == nil {
			return nil, fmt.Errorf("cannot create workload object from nil core object")
		}
		res.Name = actualObj.Name
		res.Namespace = actualObj.ObjectMeta.Namespace
		res.Labels = make(map[string]string, len(actualObj.Spec.Template.Labels))
		res.Ports = make([]corev1.ContainerPort, 0, defaultPortsListSize)
		for k, v := range actualObj.Spec.Template.Labels {
			res.Labels[k] = v
		}
		for i := range actualObj.Spec.Template.Spec.Containers {
			res.Ports = append(res.Ports, actualObj.Spec.Template.Spec.Containers[i].Ports...)
		}
		res.Variant = variantFromLabelsMap(res.Labels)
	}
	return res, nil
}

// WorkloadFromPodObject: create a Workload object from a Pod's OwnerReferences
func WorkloadFromPodObject(p *corev1.Pod) (*Workload, error) {
	hasOwner := false
	res := &Workload{}
	for refIndex := range p.ObjectMeta.OwnerReferences {
		ownerRef := p.ObjectMeta.OwnerReferences[refIndex]
		if *ownerRef.Controller {
			hasOwner = true
			res.Name = ownerRef.Name
			res.Kind = ownerRef.Kind
			res.Namespace = p.Namespace
			break
		}
	}
	if !hasOwner {
		return nil, fmt.Errorf("Pod %v has no owner", p.Name)
	}

	// update owner's workload with labels and ports from the pod object
	res.Labels = make(map[string]string, len(p.Labels))
	for k, v := range p.Labels {
		res.Labels[k] = v
	}

	res.Ports = make([]corev1.ContainerPort, 0, defaultPortsListSize)
	for i := range p.Spec.Containers {
		res.Ports = append(res.Ports, p.Spec.Containers[i].Ports...)
	}

	res.Variant = variantFromLabelsMap(p.Labels)
	res.CountOwnedPods = 1

	return res, nil
}

// return a pod owner name if exists, else an empty string
func getPodOwnerName(p *corev1.Pod) string {
	var res string
	for refIndex := range p.ObjectMeta.OwnerReferences {
		ownerRef := p.ObjectMeta.OwnerReferences[refIndex]
		// There cannot be more than one managing controller.
		if *ownerRef.Controller {
			res = ownerRef.Name
			break
		}
	}
	return res
}

// GetPodOwnerKey: get owner key in the form of "owner-ns/owner-name/variant"
func GetPodOwnerKey(p *corev1.Pod) string {
	ownerName := getPodOwnerName(p)
	if ownerName == "" {
		return ""
	}
	ownerNs := p.Namespace
	variant := variantFromLabelsMap(p.Labels)
	return ownerNs + separator + ownerName + separator + variant
}

func variantFromLabelsMap(labels map[string]string) string {
	s := fmt.Sprintf("%v", labels)
	h := sha1.New() //nolint:gosec
	h.Write([]byte(s))
	sha1Hash := hex.EncodeToString(h.Sum(nil))
	return sha1Hash
}
