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
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

const defaultPortsListSize = 8

// Pod encapsulats k8s Pod fields that are relevant for evaluating network policies
type Pod struct {
	Name      string
	Namespace string
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
			pr.Owner.Name = ownerRef.Name
			pr.Owner.Kind = ownerRef.Kind
			pr.Owner.APIVersion = ownerRef.APIVersion
			pr.Owner.Variant = variantFromLabelsMap(p.Labels)
			break
		}
	}
	return pr, nil
}

// canonical Pod name
func namespacedName(pod *corev1.Pod) string {
	return types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}.String()
}

func variantFromLabelsMap(labels map[string]string) string {
	s := fmt.Sprintf("%v", labels)
	h := sha1.New() //nolint:gosec
	h.Write([]byte(s))
	sha1Hash := hex.EncodeToString(h.Sum(nil))
	return sha1Hash
}
