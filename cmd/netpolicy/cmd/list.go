// Copyright 2022
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/common"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/connlist"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/logger"
)

var (
	focusWorkload string
	output        string // output format
	outFile       string // output file
)

func getOutputFormatDescription(validFormats string) string {
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
	if includeJSONManifests {
		res = append(res, connlist.WithIncludeJSONManifests())
	}
	if stopOnFirstError {
		res = append(res, connlist.WithStopOnError())
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
	// output format - default txt
	supportedFormats := strings.Join(connlist.ValidFormats, ",")
	c.Flags().StringVarP(&output, "output", "o", common.DefaultFormat, getOutputFormatDescription(supportedFormats))
	// out file
	c.Flags().StringVarP(&outFile, "file", "f", "", "Write output to specified file")
	return c
}
