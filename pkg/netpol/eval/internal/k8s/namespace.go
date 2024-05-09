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
	corev1 "k8s.io/api/core/v1"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/common"
)

// Namespace encapsulates k8s namespace fields that are relevant for evaluating network policies
type Namespace struct {
	Name   string
	Labels map[string]string
}

// @todo need a Namespace collection type along with convenience methods?
// 	if so, also consider concurrent access (or declare not goroutine safe?)

// FromCoreObject creates a PodRef by extracting relevant fields from the k8s Pod
func NamespaceFromCoreObject(ns *corev1.Namespace) (*Namespace, error) {
	n := &Namespace{
		Name:   ns.Name,
		Labels: make(map[string]string, len(ns.Labels)),
	}

	for k, v := range ns.Labels {
		n.Labels[k] = v
	}
	// @todo/tbd : should also add the name label as "name:<val>"  or assume policy rules
	// selecting a namespace with name labels always use "kubernetes.io/metadata.name"
	// if missing, the label set by k8s API server must be added to the namespace labels
	if _, ok := n.Labels[common.K8sNsNameLabelKey]; !ok {
		n.Labels[common.K8sNsNameLabelKey] = ns.Name
	}

	return n, nil
}
