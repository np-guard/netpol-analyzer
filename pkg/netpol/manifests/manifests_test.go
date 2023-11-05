package manifests

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/testutils"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/logger"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/scan"
)

//nolint:gocritic //temporary commented-out code
func TestBasic(t *testing.T) {
	dirPath := filepath.Join(testutils.GetTestsDir(), "basic")
	rList, errs := GetResourceInfosFromDirPath([]string{dirPath}, true, false)
	require.Empty(t, errs, "expecting no errors on basic dir")

	// TODO: move the code below to scan pkg
	oList, _ := scan.ResourceInfoListToK8sObjectsList(rList, logger.NewDefaultLogger(), false)
	// require.Nil(t, err, "err ResourceInfoToK8sObjects")
	require.Equal(t, len(oList), len(rList), "expecting same length fot input and output lists")
	fmt.Println("done")
}
