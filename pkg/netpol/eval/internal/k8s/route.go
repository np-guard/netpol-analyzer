// Copyright 2022
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package k8s

import (
	"errors"

	ocroutev1 "github.com/openshift/api/route/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/scan"
)

// Route encapsulates openshift route fields that are relevant for ingress traffic analysis
type Route struct {
	Name           string
	Namespace      string
	TargetServices []string
}

const (
	maxBackendServices = 3
	allowedTargetKind  = scan.Service
	routeTargetKindErr = "target kind error"
	routeBackendsErr   = "alternate backends error"
)

func errorMessage(routeStr, routeErr string) string {
	return scan.Route + " " + routeStr + ": " + routeErr
}

func RouteFromOCObject(rtObj *ocroutev1.Route) (*Route, error) {
	routeStr := types.NamespacedName{Namespace: rtObj.Namespace, Name: rtObj.Name}.String()
	// Currently, only 'Service' is allowed as the kind of target that the route is referring to.
	if rtObj.Spec.To.Kind != "" && rtObj.Spec.To.Kind != allowedTargetKind {
		return nil, errors.New(errorMessage(routeStr, routeTargetKindErr))
	}
	if len(rtObj.Spec.AlternateBackends) > maxBackendServices {
		return nil, errors.New(errorMessage(routeStr, routeBackendsErr))
	}

	targetSvcs := make([]string, len(rtObj.Spec.AlternateBackends)+1)
	targetSvcs[0] = rtObj.Spec.To.Name
	for i, backend := range rtObj.Spec.AlternateBackends {
		if backend.Kind != "" && backend.Kind != allowedTargetKind {
			return nil, errors.New(errorMessage(routeStr, routeBackendsErr))
		}
		targetSvcs[i+1] = backend.Name
	}

	rt := &Route{
		Name:           rtObj.Name,
		Namespace:      rtObj.Namespace,
		TargetServices: targetSvcs,
	}

	return rt, nil
}
