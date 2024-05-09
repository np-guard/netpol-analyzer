/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
	outconsts "github.com/np-guard/netpol-analyzer/pkg/internal/output"
	"github.com/np-guard/netpol-analyzer/pkg/logger"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/diff"
)

var (
	dir1      string
	dir2      string
	outFormat string
)

const (
	dir1Arg = "dir1"
	dir2Arg = "dir2"
)

func runDiffCommand() error {
	var connsDiff diff.ConnectivityDiff
	var err error

	clogger := logger.NewDefaultLoggerWithVerbosity(detrmineLogVerbosity())
	diffAnalyzer := diff.NewDiffAnalyzer(getDiffOptions(clogger)...)

	connsDiff, err = diffAnalyzer.ConnDiffFromDirPaths(dir1, dir2)
	if err != nil {
		return err
	}
	out, err := diffAnalyzer.ConnectivityDiffToString(connsDiff)
	if err != nil {
		return err
	}
	fmt.Printf("%s", out)
	if outFile != "" {
		return writeBufToFile(outFile, []byte(out))
	}
	return nil
}

func getDiffOptions(l *logger.DefaultLogger) []diff.DiffAnalyzerOption {
	res := []diff.DiffAnalyzerOption{diff.WithLogger(l), diff.WithOutputFormat(outFormat), diff.WithArgNames(dir1Arg, dir2Arg)}
	if stopOnFirstError {
		res = append(res, diff.WithStopOnError())
	}
	return res
}

func newCommandDiff() *cobra.Command {
	c := &cobra.Command{
		Use:   "diff",
		Short: "Reports semantic-diff of allowed connectivity ",
		Long:  `Reports all differences in allowed connections between two different directories of YAML manifests.`,
		Example: ` # Get list of different allowed connections between two resources dir paths
		k8snetpolicy diff --dir1 ./resources_dir/ --dir2 ./other_resources_dir/`,

		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if dirPath != "" {
				return errors.New(netpolerrors.FlagMisUseErr)
			}
			if dir1 == "" || dir2 == "" {
				return errors.New(netpolerrors.RequiredFlagsErr)
			}
			if err := diff.ValidateDiffOutputFormat(outFormat); err != nil {
				return err
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
	c.Flags().StringVarP(&dir1, dir1Arg, "", "", "Original Resources path to be compared")
	c.Flags().StringVarP(&dir2, dir2Arg, "", "", "New Resources path to compare with original resources path")
	supportedDiffFormats := strings.Join(diff.ValidDiffFormats, ",")
	c.Flags().StringVarP(&outFormat, "output", "o", outconsts.DefaultFormat, getRequiredOutputFormatString(supportedDiffFormats))
	// out file
	c.Flags().StringVarP(&outFile, "file", "f", "", "Write output to specified file")
	return c
}
