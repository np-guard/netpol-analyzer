package netpol

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/netpol-analyzer/pkg/logger"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/fsscanner"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/parser"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/testutils"
)

func TestBasic(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDirWithDepth(2), "basic")
	rList, errs := fsscanner.GetResourceInfosFromDirPath([]string{dirPath}, true, false)
	require.Empty(t, errs, "expecting no errors on basic dir")

	// TODO: move the code below to parser pkg
	oList, _ := parser.ResourceInfoListToK8sObjectsList(rList, logger.NewDefaultLogger(), false)
	require.Equal(t, len(oList), len(rList), "expecting same length fot input and output lists")
	fmt.Println("done")
}
