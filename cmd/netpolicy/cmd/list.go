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

	"github.com/spf13/cobra"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "Lists all allowed connections",
	Long: `Lists all allowed connections based on the workloads and network policies
defined`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("list called")
	},
}

// define any flags and configuration settings.
// Use PersistentFlags() for flags inherited by subcommands or Flags() for local flags.
func init() {
	rootCmd.AddCommand(listCmd)
}
