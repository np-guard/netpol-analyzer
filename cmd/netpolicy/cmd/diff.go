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
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/diff"
)

var (
	dir1 string
	dir2 string
)

func runDiffCommand() error {
	var connsDiff diff.ConnectivityDiff
	var err error

	diffAnalyzer := diff.NewDiffAnalyzer()

	connsDiff, err = diffAnalyzer.ConnDiffFromDirPaths(dir1, dir2)
	if err != nil {
		return err
	}
	out, err := connsDiff.String()
	if err != nil {
		return err
	}
	fmt.Printf("%s", out)
	return nil
}

func newCommandDiff() *cobra.Command {
	c := &cobra.Command{
		Use:   "diff",
		Short: "Reports changed connections",
		Long:  `Reports all changd connections between different networkpolicies sets`,
		Example: ` # Get list of different allowed connections between two resources dir paths
		k8snetpolicy diff --dir1 ./resources_dir/ --dir2 ./other_resources_dir/`,

		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if dirPath != "" {
				return errors.New("dirpath flag is not used with diff command")
			}
			if dir1 == "" || dir2 == "" {
				return errors.New("both directory paths dir1 and dir2 are required")
			}
			return nil
		},

		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runDiffCommand(); err != nil {
				cmd.SilenceUsage = true // don't print usage message when returning an error from running a valid command
				return err
			}
			return nil
		},
	}

	// define any flags and configuration settings.
	c.Flags().StringVarP(&dir1, "dir1", "", "", "Original Resources path to be compared")
	c.Flags().StringVarP(&dir2, "dir2", "", "", "New Resources path to compare with original resources path")

	return c
}
