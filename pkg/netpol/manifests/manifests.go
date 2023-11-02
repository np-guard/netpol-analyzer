package manifests

import (
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
		if agg, ok := err.(utilerrors.Aggregate); ok {
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
