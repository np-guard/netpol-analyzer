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
	"strings"

	"github.com/spf13/cobra"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/connlist"
)

var (
	focusWorkload string
	// output format
	output string
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "Lists all allowed connections",
	Long: `Lists all allowed connections based on the workloads and network policies
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
		if rootCmd.PersistentPreRunE != nil {
			if err := rootCmd.PersistentPreRunE(cmd, args); err != nil {
				return err
			}
		}
		return nil
	},

	RunE: func(cmd *cobra.Command, args []string) error {

		var conns []connlist.Peer2PeerConnection
		var err error

		analyzer := connlist.NewConnlistAnalyzer(connlist.WithFocusWorkload(focusWorkload), connlist.WithOutputFormat(output))

		if dirPath != "" {
			conns, err = analyzer.ConnlistFromDirPath(dirPath)
		} else {
			conns, err = analyzer.ConnlistFromK8sCluster(clientset)
		}
		if err != nil {
			return err
		}
		out, err := analyzer.ConnectionsListToString(conns)
		if err != nil {
			return err
		}
		fmt.Printf("%s", out)

		return nil
	},
}

// define any flags and configuration settings.
// Use PersistentFlags() for flags inherited by subcommands or Flags() for local flags.
func init() {
	rootCmd.AddCommand(listCmd)

	// output options
	listCmd.Flags().StringVarP(&focusWorkload, "focusworkload", "",
		focusWorkload, "Focus connections of specified workload name in the output")
	// output format - default txt
	supportedFormats := strings.Join(connlist.ValidFormats, ",")
	listCmd.Flags().StringVarP(&output, "output", "o", connlist.DefaultFormat, "Required output format ("+supportedFormats+")")
}
