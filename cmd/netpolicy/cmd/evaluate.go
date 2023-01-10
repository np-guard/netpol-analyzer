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
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/scan"
)

// TODO: consider using k8s.io/cli-runtime/pkg/genericclioptions to load kube config.
// 		Currently adds many options flags, so wait until cobra supports something
// 		like NamedFlagSet's.

var (
	// evaluated connection information
	protocol       = "tcp"
	sourcePod      = types.NamespacedName{Namespace: "default"}
	destinationPod = types.NamespacedName{Namespace: "default"}
	srcExternalIP  string
	dstExternalIP  string
	port           string
)

// evaluateCmd represents the evaluate command
var evaluateCmd = &cobra.Command{
	Use:     "evaluate",
	Short:   "Evaluate if a specific connection allowed",
	Aliases: []string{"eval", "check", "allow"}, // TODO: close on fewer, consider changing command name?
	Example: `  # Evaluate if a specific connection is allowed on given resources from dir path
  k8snetpolicy eval --dirpath ./resources_dir/ -s default/pod-1 -d default/pod-2 -p 80
  
  # Evaluate if a specific connection is allowed on a live k8s cluster
  k8snetpolicy eval -k ./kube/config -s default/pod-1 -d default/pod-2 -p 80`,

	// TODO: can this check be done in an Args function (e.g., incl. built-in's such as MinArgs(3))?
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Call parent pre-run
		if rootCmd.PersistentPreRunE != nil {
			if err := rootCmd.PersistentPreRunE(cmd, args); err != nil {
				return err
			}
		}

		// Validate flags values
		if sourcePod.Name == "" && srcExternalIP == "" {
			return errors.New("no source defined, source pod and namespace or external IP required")
		} else if sourcePod.Name != "" && srcExternalIP != "" {
			return errors.New("only one of source pod and namespace or external IP can be defined, not both")
		}

		if destinationPod.Name == "" && dstExternalIP == "" {
			return errors.New("no destination defined, destination pod and namespace or external IP required")
		} else if destinationPod.Name != "" && dstExternalIP != "" {
			return errors.New("only one of destination pod and namespace or external IP can be defined, not both")
		}

		if srcExternalIP != "" && dstExternalIP == "" {
			return errors.New("only one of source or destination can be defined as external IP, not both")
		}

		if port == "" {
			return errors.New("destination port name or value is required")
		}

		return nil
	},

	RunE: func(cmd *cobra.Command, args []string) error {
		nsNames := []string{}
		podNames := []types.NamespacedName{}

		destination := dstExternalIP
		if destination == "" {
			destination = destinationPod.String()
			nsNames = append(nsNames, destinationPod.Namespace)
			podNames = append(podNames, destinationPod)
		}

		source := srcExternalIP
		if source == "" {
			source = sourcePod.String()
			nsNames = append(nsNames, sourcePod.Namespace)
			podNames = append(podNames, sourcePod)
		}

		pe := eval.NewPolicyEngine()

		if dirPath != "" {
			// get relevant resources from dir path
			objectsList, err := scan.FilesToObjectsListFiltered(dirPath, filepath.WalkDir, podNames)
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
			// get relevant resources from k8s live cluster
			var err error
			const ctxTimeoutSeconds = 3
			ctx := context.Background()
			ctx, cancel := context.WithTimeout(ctx, ctxTimeoutSeconds*time.Second)
			defer cancel()

			for _, name := range nsNames {
				ns, apierr := clientset.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
				if apierr != nil {
					return apierr
				}
				if err = pe.UpsertObject(ns); err != nil {
					return err
				}
			}

			for _, name := range podNames {
				pod, apierr := clientset.CoreV1().Pods(name.Namespace).Get(ctx, name.Name, metav1.GetOptions{})
				if apierr != nil {
					return apierr
				}
				if err = pe.UpsertObject(pod); err != nil {
					return err
				}
			}

			for _, ns := range nsNames {
				npList, apierr := clientset.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
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

		allowed, err := pe.CheckIfAllowed(source, destination, protocol, port)
		if err != nil {
			return err
		}

		// @todo: use a logger instead?
		fmt.Printf("%v => %v over %s/%s: %t\n", source, destination, protocol, port, allowed)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(evaluateCmd)

	// connection definition
	evaluateCmd.Flags().StringVarP(&sourcePod.Name, "source-pod", "s",
		sourcePod.Name, "Source pod name, required")
	evaluateCmd.Flags().StringVarP(&sourcePod.Namespace, "source-namespace", "n",
		sourcePod.Namespace, "Source pod namespace")
	evaluateCmd.Flags().StringVarP(&destinationPod.Name, "destination-pod", "d",
		destinationPod.Name, "Destination pod name")
	evaluateCmd.Flags().StringVarP(&destinationPod.Namespace, "destination-namespace", "",
		destinationPod.Namespace, "Destination pod namespace")
	evaluateCmd.Flags().StringVarP(&srcExternalIP, "source-ip", "",
		srcExternalIP, "Source (external) IP address")
	evaluateCmd.Flags().StringVarP(&dstExternalIP, "destination-ip", "",
		dstExternalIP, "Destination (external) IP address")
	evaluateCmd.Flags().StringVarP(&port, "destination-port", "p", port, "Destination port (name or number)")
	evaluateCmd.Flags().StringVarP(&protocol, "protocol", "", protocol, "Protocol in use (tcp, udp, sctp)")
}
