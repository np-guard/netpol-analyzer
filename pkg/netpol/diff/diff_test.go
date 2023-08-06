package diff

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/common"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/internal/testutils"
)

type testEntry struct {
	firstDirName      string
	secondDirName     string
	formats           []string
	isErr             bool
	expectedOutputErr string
}

const expectedOutputFilePrefix = "diff_output_from_"

var allFormats = []string{common.TextFormat, common.MDFormat, common.CSVFormat}

func TestDiff(t *testing.T) {
	testingEntries := []testEntry{
		{
			// description:
			// **changed netpols: default/frontend-netpol, default/adservice-netpol, default/checkoutservice-netpol,
			// 		default/cartservice-netpol, default/currencyservice-netpol, default/emailservice-netpol
			// **added netpols : default/redis-cart-netpol
			firstDirName:  "onlineboutique_workloads",
			secondDirName: "onlineboutique_workloads_changed_netpols",
			formats:       allFormats,
			isErr:         false,
		},
		// {
		// 	// description:
		// 	// **changed netpols: default/frontend-netpol, default/adservice-netpol, default/checkoutservice-netpol,
		// 	// 		default/cartservice-netpol, default/currencyservice-netpol, default/emailservice-netpol
		// 	// **added netpols : default/redis-cart-netpol
		// 	// **added workloads: default/unicorn
		// 	firstDirName:  "onlineboutique_workloads",
		// 	secondDirName: "onlineboutique_workloads_changed_netpols_and_workloads",
		// 	formats:       allFormats,
		// 	isErr:         false,
		// },
		// {
		// 	// description:
		// 	// **added workloads: default/unicorn
		// 	firstDirName:  "onlineboutique_workloads",
		// 	secondDirName: "onlineboutique_workloads_changed_workloads",
		// 	formats:       allFormats,
		// 	isErr:         false,
		// },
		// {
		// 	firstDirName:      "onlineboutique_workloads",
		// 	secondDirName:     "onlineboutique_workloads_changed_netpols",
		// 	formats:           []string{"png"},
		// 	isErr:             true,
		// 	expectedOutputErr: "png output format is not supported.",
		// },
		// {
		// 	// description:
		// 	// **changed netpols: default/frontend-netpol
		// 	// **added Ingress: default/onlineboutique-ingress
		// 	firstDirName:  "onlineboutique_workloads",
		// 	secondDirName: "onlineboutique_workloads_with_ingress",
		// 	formats:       []string{common.CSVFormat},
		// },
		// {
		// 	// description:
		// 	// ** changed Ingress:  default/ingress-policy
		// 	// ** added netpols: default/productpage-netpol, default/details-netpol, default/reviews-netpol,
		// 	//		 default/ratings-netpol
		// 	// **added workloads: default/unicorn
		// 	firstDirName:  "k8s_ingress_test",
		// 	secondDirName: "k8s_ingress_test_new",
		// 	formats:       allFormats,
		// 	isErr:         false,
		// },
		// {
		// 	// description:
		// 	// **changed workloads : backend/catalog (removed port)
		// 	// **added workloads: external/unicorn
		// 	// **removed workloads: payments/mastercard-processor
		// 	// **changed netpols: frontend/asset-cache-netpol (blocked ingress), backend/catalog-netpol, backend/reports-netpol,
		// 	//			backend/shipping-netpol, frontend/webapp-netpol,
		// 	firstDirName:  "acs-security-demos",
		// 	secondDirName: "acs-security-demos-new",
		// 	formats:       allFormats,
		// 	isErr:         false,
		// },
		// {
		// 	// description:
		// 	// **removed Routes: frontend/asset-cache, frontend/webapp
		// 	firstDirName:  "acs-security-demos",
		// 	secondDirName: "acs-security-demos-no-routes",
		// 	formats:       []string{common.DefaultFormat},
		// },
		// {
		// 	// description:
		// 	// **removed Ingress: ingressworld/ingress-2
		// 	// **added Route: ingressworld/route-1
		// 	firstDirName:  "multiple_ingress_objects_with_different_ports",
		// 	secondDirName: "multiple_ingress_objects_with_different_ports_new",
		// 	formats:       allFormats,
		// },
		// {
		// 	// description:
		// 	// changed netpols : default/limit-app1-traffic
		// 	// in first dir connlist, default/deployment1 does not appear even it exists, since the netpol denies all traffic from/to it
		// 	// in second dir , the netpol limits the ingress of it , so it appears in the diff
		// 	firstDirName:  "deny_all_to_from_a_deployment",
		// 	secondDirName: "deny_all_to_from_a_deployment_changed_netpol",
		// 	formats:       []string{common.DefaultFormat},
		// },
	}

	for _, entry := range testingEntries {
		firstDirPath := filepath.Join(testutils.GetTestsDir(), entry.firstDirName)
		secondDirPath := filepath.Join(testutils.GetTestsDir(), entry.secondDirName)
		for _, format := range entry.formats {
			expectedOutputFileName := expectedOutputFilePrefix + entry.firstDirName + "." + format
			expectedOutputFilePath := filepath.Join(secondDirPath, expectedOutputFileName)

			diffAnalyzer := NewDiffAnalyzer(WithOutputFormat(format))
			connsDiff, err := diffAnalyzer.ConnDiffFromDirPaths(firstDirPath, secondDirPath)
			require.Empty(t, err)
			actualOutput, err := diffAnalyzer.ConnectivityDiffToString(connsDiff)
			if entry.isErr {
				require.Equal(t, err.Error(), entry.expectedOutputErr)
			} else {
				require.Empty(t, err)
				expectedOutputStr, err := os.ReadFile(expectedOutputFilePath)
				require.Empty(t, err)
				require.Equal(t, string(expectedOutputStr), actualOutput)
			}
		}
	}
}
