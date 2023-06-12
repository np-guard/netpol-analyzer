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
)

// Service encapsulates k8s service fields that are relevant for evaluating network policies
type Service struct {
	Name      string
	Namespace string
	selectors map[string]string
	// todo : support ports field?!
}

func ServiceFromCoreObject(svcObj *corev1.Service) (*Service, error) {
	svc := &Service{
		Name:      svcObj.Name,
		Namespace: svcObj.Namespace,
		selectors: make(map[string]string, len(svcObj.Spec.Selector)),
	}

	for k, v := range svcObj.Spec.Selector {
		svc.selectors[k] = v
	}

	return svc, nil
}
