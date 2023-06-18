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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Service encapsulates k8s service fields that are relevant for connectivity analysis
type Service struct {
	Name      string
	Namespace string
	Selectors map[string]string
	// todo : support ports field?!
}

func ServiceFromCoreObject(svcObj *corev1.Service) (*Service, error) {
	svc := &Service{
		Name:      svcObj.Name,
		Namespace: svcObj.Namespace,
		Selectors: make(map[string]string, len(svcObj.Spec.Selector)),
	}

	if svcObj.Spec.Selector == nil {
		return nil, errors.New("K8s Service without selectors is not supported")
	}

	if svc.Namespace == "" {
		svc.Namespace = metav1.NamespaceDefault
	}

	for k, v := range svcObj.Spec.Selector {
		svc.Selectors[k] = v
	}

	return svc, nil
}
