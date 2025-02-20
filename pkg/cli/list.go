/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	outconsts "github.com/np-guard/netpol-analyzer/pkg/internal/output"

	"github.com/np-guard/netpol-analyzer/pkg/logger"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/connlist"
)

var (
	focusWorkload          []string
	focusWorkloadPeer      []string
	focusDir               focusDirection
	exposureAnalysis       bool
	explain                bool
	explainOnlyAllowOrDeny explainOnly
	output                 string // output format
	outFile                string // output file
)

// getRequiredOutputFormatString returns the description of required format(s) of the command
func getRequiredOutputFormatString(validFormats string) string {
	return fmt.Sprintf("Required output format; must be one of %s", validFormats)
}

func runListCommand() error {
	var conns []connlist.Peer2PeerConnection
	var err error

	cLogger := logger.NewDefaultLoggerWithVerbosity(determineLogVerbosity())
	analyzer := connlist.NewConnlistAnalyzer(getConnlistOptions(cLogger)...)

	if dirPath != "" {
		conns, _, err = analyzer.ConnlistFromDirPath(dirPath)
	} else {
		conns, _, err = analyzer.ConnlistFromK8sClusterWithPolicyAPI(clientset, policyAPIClientset)
	}
	if err != nil {
		return err
	}
	out, err := analyzer.ConnectionsListToString(conns)
	if err != nil {
		return err
	}
	fmt.Printf("%s", out)

	if outFile != "" {
		return writeBufToFile(outFile, []byte(out))
	}

	return nil
}

func writeBufToFile(filepath string, buf []byte) error {
	fp, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("error creating file %s: %w", filepath, err)
	}
	_, err = fp.Write(buf)
	if err != nil {
		return fmt.Errorf("error writing to file %s: %w", filepath, err)
	}
	fp.Close()
	return nil
}

func getConnlistOptions(l *logger.DefaultLogger) []connlist.ConnlistAnalyzerOption {
	res := []connlist.ConnlistAnalyzerOption{
		connlist.WithLogger(l),
		connlist.WithFocusWorkloadList(focusWorkload),
		connlist.WithFocusWorkloadPeerList(focusWorkloadPeer),
		connlist.WithFocusDirection(focusDir.String()),
		connlist.WithExplainOnly(explainOnlyAllowOrDeny.String()),
		connlist.WithOutputFormat(output),
	}

	if stopOnFirstError {
		res = append(res, connlist.WithStopOnError())
	}
	if exposureAnalysis {
		res = append(res, connlist.WithExposureAnalysis())
	}
	if explain {
		res = append(res, connlist.WithExplanation())
	}
	return res
}

func resetInArgs() {
	focusDir.Reset()
	explainOnlyAllowOrDeny.Reset()
}

// newCommandList returns a cobra command with the appropriate configuration and flags to run list command
func newCommandList() *cobra.Command {
	resetInArgs()
	c := &cobra.Command{
		Use:   "list",
		Short: "Lists all allowed connections",
		Long: `Lists all allowed connections based on the workloads, network policies, and Ingress/Route resources
defined`,
		Example: `  # Get list of allowed connections from resources dir path
  k8snetpolicy list --dirpath ./resources_dir/ 
  
  # Get list of allowed connections from live k8s cluster
  k8snetpolicy list -k ./kube/config`,

		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := connlist.ValidateOutputFormat(output); err != nil {
				return err
			}
			// call parent pre-run
			if parent := cmd.Parent(); parent != nil {
				if parent.PersistentPreRunE != nil {
					if err := parent.PersistentPreRunE(cmd, args); err != nil {
						return err
					}
				}
			}
			return nil
		},

		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runListCommand(); err != nil {
				cmd.SilenceUsage = true // don't print usage message when returning an error from running a valid command
				return err
			}
			return nil
		},
	}

	// define any flags and configuration settings.
	// Use PersistentFlags() for flags inherited by subcommands or Flags() for local flags.
	c.Flags().StringSliceVarP(&focusWorkload, "focusworkload", "", []string{},
		"Focus connections of specified workload(s) in the output, supports comma-separated names"+
			" (workload name format: <workload-name> or <workload-namespace/workload-name>)")
	c.Flags().StringSliceVarP(&focusWorkloadPeer, "focusworkload-peer", "", []string{},
		"Focus connections of specified workload(s) with this peer(s), applies only when focusworkload is used;"+
			" supports comma-separated names (focusworkload-peer name format is same as focusworkload)")
	c.Flags().VarP(&focusDir, "focus-direction", "",
		"Focus connections of specified workload(s) on one direction, applies only when focusworkload is used; must be one of ingress,egress")
	c.Flags().BoolVarP(&exposureAnalysis, "exposure", "", false, "Enhance the analysis of permitted connectivity with exposure analysis")
	c.Flags().BoolVarP(&explain, "explain", "", false, "Enhance the analysis of permitted connectivity with explainability information")
	c.Flags().VarP(&explainOnlyAllowOrDeny, "explain-only", "",
		"Filter explain output to show only allowed or denied connections, applies only when explain is used; must be one of allow,deny")
	// output format - default txt
	supportedFormats := strings.Join(connlist.ValidFormats, ",")
	c.Flags().StringVarP(&output, "output", "o", outconsts.DefaultFormat, getRequiredOutputFormatString(supportedFormats))
	// out file
	c.Flags().StringVarP(&outFile, "file", "f", "", "Write output to specified file")

	return c
}
