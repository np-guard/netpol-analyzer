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
	"k8s.io/apimachinery/pkg/types"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
)

var (
	protocol      = "tcp"
	sourcePod     = types.NamespacedName{Namespace: "default"}
	targetPod     = types.NamespacedName{Namespace: "default"}
	srcExternalIP string
	dstExternalIP string
	port          string
	help          bool

	// @todo enable kubeconfig overrides, possibly via k8s.io/cli-runtime
)

// evaluateCmd represents the evaluate command
var evaluateCmd = &cobra.Command{
	Use:     "evaluate",
	Short:   "Evaluate if a specific connection allowed",
	Aliases: []string{"eval", "check", "allow"},

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

	evaluateCmd.Flags().StringVarP(&sourcePod.Name, "source-pod", "", sourcePod.Name, "source pod name, required")
	evaluateCmd.Flags().StringVarP(&sourcePod.Namespace, "source-namespace", "n", sourcePod.Namespace, "source pod namespace")
	evaluateCmd.Flags().StringVarP(&targetPod.Name, "destination-pod", "", targetPod.Name, "destination pod name")
	evaluateCmd.Flags().StringVarP(&targetPod.Namespace, "destination-namespace", "", targetPod.Namespace, "destination pod namespace")
	evaluateCmd.Flags().StringVarP(&srcExternalIP, "source-ip", "s", srcExternalIP, "source (external) IP")
	evaluateCmd.Flags().StringVarP(&dstExternalIP, "destination-ip", "d", dstExternalIP, "destination (external) IP")
	evaluateCmd.Flags().StringVarP(&port, "destination-port", "p", port, "destination port (name or number)")
	evaluateCmd.Flags().StringVarP(&protocol, "protocol", "", protocol, "protocol in use (tcp, udp, sctp)")
	evaluateCmd.Flags().BoolVarP(&help, "help", "h", false, "display help")
}
