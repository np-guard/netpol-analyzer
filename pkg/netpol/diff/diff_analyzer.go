package diff

import (
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/cli-runtime/pkg/resource"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/logger"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/manifests/fsscanner"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/manifests/parser"
)

// A DiffAnalyzer provides API to recursively scan two directories for Kubernetes resources including network policies,
// and get the difference of permitted connectivity between the workloads of the K8s application managed in theses directories.
type DiffAnalyzer struct {
	logger       logger.Logger
	stopOnError  bool
	errors       []DiffError
	outputFormat string
	ref1Name     string
	ref2Name     string
}

// ConnDiffFromResourceInfos returns the connectivity diffs from two lists of resource.Info objects,
// representing two versions of manifest sets to compare
func (da *DiffAnalyzer) ConnDiffFromResourceInfos(infos1, infos2 []*resource.Info) (ConnectivityDiff, error) {
	// connectivity analysis for first dir
	// TODO: should add input arg dirPath to this API func? so that log msgs can specify the dir, rather then just "ref1"/"ref2"
	conns1, workloads1, shouldStop, cDiff, errVal := da.getConnlistAnalysis(infos1, true, "")
	if shouldStop {
		return cDiff, errVal
	}

	// connectivity analysis for second dir
	conns2, workloads2, shouldStop, cDiff, errVal := da.getConnlistAnalysis(infos2, false, "")
	if shouldStop {
		return cDiff, errVal
	}

	// the actual diff analysis
	return da.computeDiffFromConnlistResults(conns1, conns2, workloads1, workloads2)
}

// ConnDiffFromDirPaths returns the connectivity diffs from two dir paths containing k8s resources,
// representing two versions of manifest sets to compare
func (da *DiffAnalyzer) ConnDiffFromDirPaths(dirPath1, dirPath2 string) (ConnectivityDiff, error) {
	// attempt to read manifests from both dirs
	infos1, errs1 := fsscanner.GetResourceInfosFromDirPath([]string{dirPath1}, true, da.stopOnError)
	infos2, errs2 := fsscanner.GetResourceInfosFromDirPath([]string{dirPath2}, true, da.stopOnError)

	if len(errs1) > 0 || len(errs2) > 0 {
		if (len(infos1) == 0 && len(infos2) == 0) || da.stopOnError || !doBothInputDirsExist(dirPath1, dirPath2) {
			err := utilerrors.NewAggregate(append(errs1, errs2...))
			dirPath := dirPath1
			if len(errs1) == 0 {
				dirPath = dirPath2
			}
			da.logger.Errorf(err, "Error getting resourceInfos from dir paths %s/%s ", da.ref1Name, da.ref2Name)
			da.errors = append(da.errors, parser.FailedReadingFile(dirPath, err))
			return nil, err // return as fatal error if both infos-lists are empty, or if stopOnError is on,
			// or if at least one input dir does not exist
		}

		// split err if it's an aggregated error to a list of separate errors
		errReadingFile := "error reading file"
		for _, err := range errs1 {
			da.logger.Errorf(err, da.errPrefixSpecifyRefName(true)+errReadingFile) // print to log the error from builder
			da.errors = append(da.errors, parser.FailedReadingFile(dirPath1, err)) // add the error from builder to accumulated errors
		}
		for _, err := range errs2 {
			da.logger.Errorf(err, da.errPrefixSpecifyRefName(false)+errReadingFile) // print to log the error from builder
			da.errors = append(da.errors, parser.FailedReadingFile(dirPath2, err))  // add the error from builder to accumulated errors
		}
	}
	return da.ConnDiffFromResourceInfos(infos1, infos2)
}
