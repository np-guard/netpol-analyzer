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
	focusWorkload    string
	exposureAnalysis bool
	output           string // output format
	outFile          string // output file
)

// getRequiredOutputFormatString returns the description of required format(s) of the command
func getRequiredOutputFormatString(validFormats string) string {
	return fmt.Sprintf("Required output format (%s)", validFormats)
}

func runListCommand() error {
	var conns []connlist.Peer2PeerConnection
	var err error

	clogger := logger.NewDefaultLoggerWithVerbosity(detrmineLogVerbosity())
	analyzer := connlist.NewConnlistAnalyzer(getConnlistOptions(clogger)...)

	if dirPath != "" {
		conns, _, err = analyzer.ConnlistFromDirPath(dirPath)
	} else {
		conns, _, err = analyzer.ConnlistFromK8sCluster(clientset)
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
		connlist.WithFocusWorkload(focusWorkload),
		connlist.WithOutputFormat(output),
	}

	if stopOnFirstError {
		res = append(res, connlist.WithStopOnError())
	}
	if exposureAnalysis {
		res = append(res, connlist.WithExposureAnalysis())
	}
	return res
}

// newCommandList returns a cobra command with the appropriate configuration and flags to run list command
func newCommandList() *cobra.Command {
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
	c.Flags().StringVarP(&focusWorkload, "focusworkload", "", "",
		"Focus connections of specified workload in the output (<workload-name> or <workload-namespace/workload-name>)")
	c.Flags().BoolVarP(&exposureAnalysis, "exposure", "", false, "Turn on exposure analysis and append results to the output")
	// output format - default txt
	// output format - default txt
	supportedFormats := strings.Join(connlist.ValidFormats, ",")
	c.Flags().StringVarP(&output, "output", "o", outconsts.DefaultFormat, getRequiredOutputFormatString(supportedFormats))
	// out file
	c.Flags().StringVarP(&outFile, "file", "f", "", "Write output to specified file")

	return c
}
