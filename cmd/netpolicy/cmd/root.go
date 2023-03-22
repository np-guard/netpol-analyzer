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
	"os"

	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	// cluster access information
	kubecontext string
	kubeconfig  string
	// resources dir information
	dirPath string
	// output format
	output string
	// k8s client
	clientset *kubernetes.Clientset
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "k8snetpolicy",
	Short: "Determine allowed connection based on Kubernetes NetworkPolicy objects",

	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
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
		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

// define any flags and configuration settings
func init() {
	// resources dir path
	rootCmd.PersistentFlags().StringVarP(&dirPath, "dirpath", "",
		dirPath, "Resources dir path when evaluating connections from a dir")
	// output format
	rootCmd.PersistentFlags().StringVarP(&output, "output", "o", output, "Required output format (txt, json) (default value: txt)")
	// cluster access
	config := os.Getenv(clientcmd.RecommendedConfigPathEnvVar)
	if config == "" {
		config = clientcmd.RecommendedHomeFile
	}
	rootCmd.PersistentFlags().StringVarP(&kubeconfig, clientcmd.RecommendedConfigPathFlag, "k", config,
		"Path and file to use for kubeconfig when evaluating connections in a live cluster")
	rootCmd.PersistentFlags().StringVarP(&kubecontext, clientcmd.FlagContext, "c", "",
		"Kubernetes context to use when evaluating connections in a live cluster")
}
