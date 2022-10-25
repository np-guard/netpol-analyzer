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

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/scan"
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

		pe := eval.NewPolicyEngine()

		if dirPath != "" {
			// get all resources from dir
			objectsList, err := scan.FilesToObjectsList(dirPath)
			if err != nil {
				return err
			}
			for _, obj := range objectsList {
				if obj.Kind == scan.Pod {
					err = pe.UpsertObject(obj.Pod)
				} else if obj.Kind == scan.Namespace {
					err = pe.UpsertObject(obj.Namespace)
				} else if obj.Kind == scan.Networkpolicy {
					err = pe.UpsertObject(obj.Networkpolicy)
				}
				if err != nil {
					return err
				}
			}
		} else {
			var err error
			// get all resources from k8s cluster

			// get all namespaces
			nsList, apierr := clientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
			if apierr != nil {
				return apierr
			}
			for i := range nsList.Items {
				ns := &nsList.Items[i]
				if err = pe.UpsertObject(ns); err != nil {
					return err
				}
			}

			// get all pods
			podList, apierr := clientset.CoreV1().Pods(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{})
			if apierr != nil {
				return apierr
			}
			for i := range podList.Items {
				if err = pe.UpsertObject(&podList.Items[i]); err != nil {
					return err
				}
			}

			// get all netpols
			npList, apierr := clientset.NetworkingV1().NetworkPolicies(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{})
			if apierr != nil {
				return apierr
			}
			for i := range npList.Items {
				if err = pe.UpsertObject(&npList.Items[i]); err != nil {
					return err
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
}
