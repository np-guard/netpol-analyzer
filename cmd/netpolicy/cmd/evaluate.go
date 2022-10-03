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
	"os"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
)

// @etail: use k8s.io/cli-runtime/pkg/genericclioptions to load kube config.
// 		Currently adds many options flags, so wait until cobra supports something
// 		like NamedFlagSet's.

var (
	help bool
	// evaluated connection information
	protocol      = "tcp"
	sourcePod     = types.NamespacedName{Namespace: "default"}
	targetPod     = types.NamespacedName{Namespace: "default"}
	srcExternalIP string
	dstExternalIP string
	port          string
	// cluster access information
	kubecontext string
	kubeconfig  string
)

// evaluateCmd represents the evaluate command
var evaluateCmd = &cobra.Command{
	Use:     "evaluate",
	Short:   "Evaluate if a specific connection allowed",
	Aliases: []string{"eval", "check", "allow"},

	// @etail: can this check be done in an Args function?
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if targetPod.Name == "" && dstExternalIP == "" {
			return errors.New("no destination defined, target-pod and namespace or external IP required")
		} else if targetPod.Name != "" && dstExternalIP != "" {
			return errors.New("only one of target-pod and namespace or external IP can be defined, not both")
		}
		if sourcePod.Name == "" && srcExternalIP == "" {
			return errors.New("no source defined, source-pod and namespace or external IP required")
		} else if sourcePod.Name != "" && srcExternalIP != "" {
			return errors.New("only one of source-pod and namespace or external IP can be defined, not both")
		}
		if srcExternalIP != "" && dstExternalIP == "" {
			return errors.New("only one of srcExternalIP or dstExternalIP can be defined, not both")
		}
		if port == "" {
			return errors.New("target port name or value is required")
		}
		return nil
	},

	Run: func(cmd *cobra.Command, args []string) {
		destination := dstExternalIP
		if destination == "" {
			destination = targetPod.String()
		}
		source := srcExternalIP
		if source == "" {
			source = sourcePod.String()
		}
		fmt.Printf("dest: %v", destination)
		fmt.Printf("source: %v", source)

		_, err := eval.CheckIfAllowed(source, destination, protocol, port)
		if err != nil {
			fmt.Printf("error CheckIfAllowed: %v", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(evaluateCmd)

	// command line flags
	evaluateCmd.Flags().BoolVarP(&help, "help", "h", false, "display help")
	// connection level flags
	evaluateCmd.Flags().StringVarP(&sourcePod.Name, "source-pod", "s", sourcePod.Name, "Source pod name, required")
	evaluateCmd.Flags().StringVarP(&sourcePod.Namespace, "source-namespace", "n", sourcePod.Namespace, "Source pod namespace")
	evaluateCmd.Flags().StringVarP(&targetPod.Name, "destination-pod", "d", targetPod.Name, "Destination pod name")
	evaluateCmd.Flags().StringVarP(&targetPod.Namespace, "destination-namespace", "", targetPod.Namespace, "Destination pod namespace")
	evaluateCmd.Flags().StringVarP(&srcExternalIP, "source-ip", "", srcExternalIP, "Source (external) IP address")
	evaluateCmd.Flags().StringVarP(&dstExternalIP, "destination-ip", "", dstExternalIP, "Destination (external) IP address")
	evaluateCmd.Flags().StringVarP(&port, "destination-port", "p", port, "Destination port (name or number)")
	evaluateCmd.Flags().StringVarP(&protocol, "protocol", "", protocol, "Protocol in use (tcp, udp, sctp)")
	// cluster access flags
	config := os.Getenv(clientcmd.RecommendedConfigPathEnvVar)
	if config == "" {
		config = clientcmd.RecommendedHomeFile
	}
	evaluateCmd.Flags().StringVarP(&kubeconfig, clientcmd.RecommendedConfigPathFlag, "k", config,
		"Path and file to use for kubeconfig when evaluating connections in a live cluster")
	evaluateCmd.Flags().StringVarP(&kubecontext, clientcmd.FlagContext, "c", "",
		"Kubernetes context to use when evaluating connections in a live cluster")
}
