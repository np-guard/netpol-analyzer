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
	"errors"

	corev1 "k8s.io/api/core/v1"
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
}

// @todo need a Pod collection type along with convenience methods?
// 	if so, also consider concurrent access (or declare not goroutine safe?)

// PodFromCoreObject creates a PodRef by extracting relevant fields from the k8s Pod
func PodFromCoreObject(p *corev1.Pod) (*Pod, error) {
	if p.Status.HostIP == "" || len(p.Status.PodIPs) == 0 { // not scheduled nor assigned IP addresses - ignore
		return nil, errors.New("no worker node or IP assigned for" + namespacedName(p))
	}

	pr := &Pod{
		Name:      p.Name,
		Namespace: p.Namespace,
		Labels:    make(map[string]string, len(p.Labels)),
		IPs:       make([]corev1.PodIP, len(p.Status.PodIPs)),
		Ports:     make([]corev1.ContainerPort, 0, defaultPortsListSize),
		HostIP:    p.Status.HostIP,
	}

	copy(pr.IPs, p.Status.PodIPs)

	for k, v := range p.Labels {
		pr.Labels[k] = v
	}

	for i := range p.Spec.Containers {
		pr.Ports = append(pr.Ports, p.Spec.Containers[i].Ports...)
	}

	return pr, nil
}

// canonical Pod name
func namespacedName(pod *corev1.Pod) string {
	return pod.Namespace + "/" + pod.Name
}
