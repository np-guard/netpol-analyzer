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
	"fmt"

	ocroutev1 "github.com/openshift/api/route/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/scan"
)

// Route encapsulates openshift route fields that are relevant for ingress traffic analysis
type Route struct {
	Name      string
	Namespace string
	TargetSvc string // service name
	// todo : should support alternateBackends ? with/without weights (rr)?
}

const (
	allowedTargetKind  = scan.Service
	routeTargetKindErr = "target kind error"
)

func RouteFromOCObject(rtObj *ocroutev1.Route) (*Route, error) {
	// Currently, only 'Service' is allowed as the kind of target that the route is referring to.
	if rtObj.Spec.To.Kind != "" && rtObj.Spec.To.Kind != allowedTargetKind {
		routeStr := types.NamespacedName{Namespace: rtObj.Namespace, Name: rtObj.Name}
		return nil, fmt.Errorf("Route %s : %s ", routeStr, routeTargetKindErr)
	}

	rt := &Route{
		Name:      rtObj.Name,
		Namespace: rtObj.Namespace,
		TargetSvc: rtObj.Spec.To.Name,
	}

	return rt, nil
}
