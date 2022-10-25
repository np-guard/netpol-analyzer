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
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/scan"
)

var (
	// resources dir information
	dirPath string
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "Lists all allowed connections",
	Long: `Lists all allowed connections based on the workloads and network policies
defined`,
	RunE: func(cmd *cobra.Command, args []string) error {

		pe := eval.NewPolicyEngine()

		// get resources from dir
		if len(dirPath) > 0 {
			objectsList, err := scan.FilesToObjectsList(dirPath)
			if err != nil {
				return err
			}
			for _, obj := range objectsList {
				if obj.Kind == "Pod" {
					err = pe.UpsertObject(obj.Pod)
				} else if obj.Kind == "Namespace" {
					err = pe.UpsertObject(obj.Namespace)
				} else if obj.Kind == "NetworkPolicy" {
					err = pe.UpsertObject(obj.Networkpolicy)
				}
				if err != nil {
					return err
				}
			}

		} else {
			// TODO: avoid code duplication here
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
			clientset, err := kubernetes.NewForConfig(k8sconf)
			if err != nil {
				return err
			}

			nsNames := []string{sourcePod.Namespace, destinationPod.Namespace}
			for _, name := range nsNames {
				ns, apierr := clientset.CoreV1().Namespaces().Get(context.TODO(), name, metav1.GetOptions{})
				if apierr != nil {
					return apierr
				}
				if err = pe.UpsertObject(ns); err != nil {
					return err
				}
			}

			podNames := []types.NamespacedName{sourcePod, destinationPod}
			for _, name := range podNames {
				pod, apierr := clientset.CoreV1().Pods(name.Namespace).Get(context.TODO(), name.Name, metav1.GetOptions{})
				if apierr != nil {
					return apierr
				}
				if err = pe.UpsertObject(pod); err != nil {
					return err
				}
			}

			for _, ns := range nsNames {
				npList, apierr := clientset.NetworkingV1().NetworkPolicies(ns).List(context.TODO(), metav1.ListOptions{})
				if apierr != nil {
					return apierr
				}
				for i := range npList.Items {
					if err = pe.UpsertObject(&npList.Items[i]); err != nil {
						return err
					}
				}
			}
		}

		// get connections map output
		// TODO: consider workloads as well
		podsMap := pe.GetPodsMap()
		for srcPod := range podsMap {
			for dstPod := range podsMap {
				allowedConnections, err := pe.AllAllowedConnections(srcPod, dstPod)
				if err == nil {
					fmt.Printf("%v => %v : %v\n", srcPod, dstPod, allowedConnections.String())
				}
			}
		}

		return nil
	},
}

// define any flags and configuration settings.
// Use PersistentFlags() for flags inherited by subcommands or Flags() for local flags.
func init() {
	rootCmd.AddCommand(listCmd)
	listCmd.Flags().StringVarP(&dirPath, "dirpath", "",
		dirPath, "resources dir path")

	// cluster access
	config := os.Getenv(clientcmd.RecommendedConfigPathEnvVar)
	if config == "" {
		config = clientcmd.RecommendedHomeFile
	}
	listCmd.Flags().StringVarP(&kubeconfig, clientcmd.RecommendedConfigPathFlag, "k", config,
		"Path and file to use for kubeconfig when evaluating connections in a live cluster")
	listCmd.Flags().StringVarP(&kubecontext, clientcmd.FlagContext, "c", "",
		"Kubernetes context to use when evaluating connections in a live cluster")
}
