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
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/connlist"
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

	RunE: func(cmd *cobra.Command, args []string) error {

		var conns []connlist.Peer2PeerConnection
		var err error

		if dirPath != "" {
			conns, err = connlist.FromDir(dirPath, filepath.WalkDir)
		} else {
			conns, err = connlist.FromK8sCluster(clientset)
		}
		if err != nil {
			return err
		}
		fmt.Printf("%v", connlist.ConnectionsListToString(conns))

		return nil
	},
}

// define any flags and configuration settings.
// Use PersistentFlags() for flags inherited by subcommands or Flags() for local flags.
func init() {
	rootCmd.AddCommand(listCmd)
}
