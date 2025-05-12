/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cli

import (
	"errors"
	"os"

	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	policyapi "sigs.k8s.io/network-policy-api/pkg/client/clientset/versioned"

	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
	"github.com/np-guard/netpol-analyzer/pkg/logger"
)

var (
	// cluster access information
	kubecontext string
	kubeconfig  string
	// resources dir information
	dirPath string
	// k8s client
	clientset          *kubernetes.Clientset
	policyAPIClientset *policyapi.Clientset
	quiet              bool
	verbose            bool
	stopOnFirstError   bool
)

// returns verbosity level based on the -q and -v switches
func determineLogVerbosity() logger.Verbosity {
	verbosity := logger.DefaultVerbosity
	if quiet {
		verbosity = logger.LowVerbosity
	} else if verbose {
		verbosity = logger.HighVerbosity
	}
	return verbosity
}

// newCommandRoot returns a cobra command with the appropriate configuration, flags and sub-commands to run the root command netpol-analyzer
func newCommandRoot() *cobra.Command {
	c := &cobra.Command{
		Use:   "netpol-analyzer",
		Short: "Determine allowed connection based on Kubernetes NetworkPolicy objects",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if quiet && verbose {
				return errors.New(netpolerrors.VerbosityFlagsMisUseErrStr)
			}
			if dirPath != "" {
				return nil
			}
			// TODO: add explicit logs to indicate progress (loading config, listing namespaces, ...)
			// TODO: use errors.Wrap for clearer error return?

			// create a k8s client with the correct config and context
			loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig}
			overrides := &clientcmd.ConfigOverrides{}
			if kubecontext != "" {
				overrides.CurrentContext = kubecontext
			}

			k8sconf, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides).ClientConfig()
			if err != nil {
				return err
			}
			clientset, err = kubernetes.NewForConfig(k8sconf)
			if err != nil {
				return err
			}
			policyAPIClientset, err = policyapi.NewForConfig(k8sconf)
			if err != nil {
				return err
			}
			return nil
		},
	}

	// define any flags and configuration settings
	// resources dir path
	c.PersistentFlags().StringVarP(&dirPath, "dirpath", "", "", "Resources dir path when evaluating connections from a dir")
	// cluster access
	config := os.Getenv(clientcmd.RecommendedConfigPathEnvVar)
	if config == "" {
		config = clientcmd.RecommendedHomeFile
	}
	c.PersistentFlags().StringVarP(&kubeconfig, clientcmd.RecommendedConfigPathFlag, "k", config,
		"Path and file to use for kubeconfig when evaluating connections in a live cluster")
	c.PersistentFlags().StringVarP(&kubecontext, clientcmd.FlagContext, "c", "",
		"Kubernetes context to use when evaluating connections in a live cluster")
	c.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "runs quietly, reports only severe errors and results")
	c.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "runs with more informative messages printed to log")
	c.PersistentFlags().BoolVarP(&stopOnFirstError, "fail", "", false, "fail on the first encountered error")

	// add sub-commands
	c.AddCommand(newCommandEvaluate())
	c.AddCommand(newCommandList())
	c.AddCommand(newCommandDiff())

	return c
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	rootCmd := newCommandRoot()
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
