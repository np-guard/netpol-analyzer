/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package parser

import (
	"errors"
	"fmt"

	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/cli-runtime/pkg/resource"
	apisv1a "sigs.k8s.io/network-policy-api/apis/v1alpha1"

	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
	"github.com/np-guard/netpol-analyzer/pkg/logger"
)

// ResourceInfoListToK8sObjectsList returns a list of K8sObject and list of FileProcessingError objects from analyzing
// an input list of resource.Info objects. Irrelevant resources are skipped.
// Possible errs/warnings as FileProcessingError:
// malformedYamlDoc , noK8sWorkloadResourcesFound, noK8sNetworkPolicyResourcesFound
func ResourceInfoListToK8sObjectsList(infosList []*resource.Info, l logger.Logger, muteErrsAndWarns bool) (
	[]K8sObject, []FileProcessingError) {
	res := make([]K8sObject, 0)
	fpErrList := []FileProcessingError{}
	var hasWorkloads, hasNetpols bool
	for _, info := range infosList {
		// fpErr can be  malformedYamlDoc
		k8sObj, fpErr := resourceInfoToK8sObject(info, l, muteErrsAndWarns)
		if fpErr != nil {
			fpErrList = append(fpErrList, *fpErr)
			// no need to stop if stopOnErr was set, since malformedYamlDoc is a warning
		}
		if k8sObj != nil && k8sObj.Kind != "" {
			res = append(res, *k8sObj)
			if k8sObj.Kind == Networkpolicy {
				hasNetpols = true
			}
			if workloadKinds[k8sObj.Kind] {
				hasWorkloads = true
			}
		}
	}
	if !hasWorkloads {
		fpErrList = appendAndLogNewError(fpErrList, noK8sWorkloadResourcesFound(), l, muteErrsAndWarns)
	}
	if !hasNetpols {
		fpErrList = appendAndLogNewError(fpErrList, noK8sNetworkPolicyResourcesFound(), l, muteErrsAndWarns)
	}

	return res, fpErrList
}

// resourceInfoToK8sObject converts an input resource.Info object to a K8sObject
func resourceInfoToK8sObject(info *resource.Info, l logger.Logger, muteErrsAndWarns bool) (
	*K8sObject, *FileProcessingError) {
	resObject := K8sObject{}
	if unstructuredObj, ok := info.Object.(*unstructured.Unstructured); ok {
		resObject.Kind = unstructuredObj.GetKind()
		var err error
		objField := resObject.getEmptyInitializedFieldObjByKind(resObject.Kind)
		if objField == nil {
			l.Infof("in file: %s, skipping object with type: %s", info.Source, resObject.Kind)
			return nil, nil
		}
		err = runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredObj.Object, objField)
		if err != nil {
			kind := unstructuredObj.GetKind()
			name := unstructuredObj.GetName()
			namespace := unstructuredObj.GetNamespace()
			// malformed k8s resource
			resourceStr := getResourceInfoStr(kind, name, namespace)
			errStr := "error for resource"
			if resourceStr != "" {
				errStr += " with " + resourceStr
			}
			fpErr := malformedYamlDoc(info.Source, 0, -1, fmt.Errorf("%s:  %w", errStr, err))
			logError(l, fpErr, muteErrsAndWarns)
			return nil, fpErr
		}
		resObject.initDefaultNamespace()
	} else {
		// failed conversion to unstructured
		fpErr := malformedYamlDoc(info.Source, 0, -1, errors.New(netpolerrors.ConversionToUnstructuredErr))
		logError(l, fpErr, muteErrsAndWarns)
		return nil, fpErr
	}

	return &resObject, nil
}

func CreatePodK8sObject(pod *v1.Pod) K8sObject {
	k8sObj := K8sObject{}
	k8sObj.Kind = "Pod"
	k8sObj.Pod = pod
	k8sObj.initDefaultNamespace()
	return k8sObj
}

func CreateNamespaceK8sObject(ns *v1.Namespace) K8sObject {
	k8sObj := K8sObject{}
	k8sObj.Kind = "Namespace"
	k8sObj.Namespace = ns
	k8sObj.initDefaultNamespace()
	return k8sObj
}

func CreateNetwordPolicyK8sObject(np *netv1.NetworkPolicy) K8sObject {
	k8sObj := K8sObject{}
	k8sObj.Kind = "NetworkPolicy"
	k8sObj.Networkpolicy = np
	k8sObj.initDefaultNamespace()
	return k8sObj
}

func CreateAdminNetwordPolicyK8sObject(anp *apisv1a.AdminNetworkPolicy) K8sObject {
	k8sObj := K8sObject{}
	k8sObj.Kind = "AdminNetworkPolicy"
	k8sObj.AdminNetworkPolicy = anp
	k8sObj.initDefaultNamespace()
	return k8sObj
}

// error for resource with kind: , name: ,namespace: ,
func getResourceInfoStr(kind, name, namespace string) string {
	res := ""
	sep := " , "
	if kind != "" {
		res += "kind: " + kind + sep
	}
	if name != "" {
		res += "name: " + name + sep
	}
	if namespace != "" {
		res += "namespace: " + namespace + sep
	}
	return res
}

func appendAndLogNewError(errs []FileProcessingError, newErr *FileProcessingError, l logger.Logger,
	muteErrsAndWarns bool) []FileProcessingError {
	logError(l, newErr, muteErrsAndWarns)
	errs = append(errs, *newErr)
	return errs
}

func logError(l logger.Logger, fpe *FileProcessingError, muteErrsAndWarns bool) {
	if muteErrsAndWarns {
		return
	}
	logMsg := fpe.Error().Error()
	location := fpe.Location()
	if location != "" {
		logMsg = fmt.Sprintf("err : %s %s", location, logMsg)
	}
	if fpe.IsSevere() || fpe.IsFatal() {
		l.Errorf(errors.New(logMsg), "")
	} else {
		l.Warnf(logMsg)
	}
}
