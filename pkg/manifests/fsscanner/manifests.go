/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package fsscanner

import (
	"errors"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/cli-runtime/pkg/resource"
)

// GetResourceInfosFromDirPath returns a list of resource.Info objects from input paths to scan
func GetResourceInfosFromDirPath(paths []string, recursive, stopOnErr bool) ([]*resource.Info, []error) {
	fileOption := resource.FilenameOptions{Filenames: paths, Recursive: recursive}
	builder := getResourceBuilder(stopOnErr, fileOption)
	resourceResult := builder.Do()
	infos, err := resourceResult.Infos()
	errs := []error{}
	if err != nil {
		var agg utilerrors.Aggregate
		if ok := errors.As(err, &agg); ok {
			errs = agg.Errors()
		} else {
			errs = []error{err}
		}
	}
	return infos, errs
}

func getResourceBuilder(stopOnErr bool, fileOption resource.FilenameOptions) *resource.Builder {
	builder := resource.NewLocalBuilder()
	res := builder.
		Unstructured().FilenameParam(false, &fileOption).
		Flatten()
	if !stopOnErr {
		res.ContinueOnError()
	}
	return res
}
