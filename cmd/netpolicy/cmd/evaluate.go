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
	"os"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
)

// @etail: use k8s.io/cli-runtime/pkg/genericclioptions to load kube config.
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
	// cluster access information
	kubecontext string
	kubeconfig  string
)

// evaluateCmd represents the evaluate command
var evaluateCmd = &cobra.Command{
	Use:     "evaluate",
	Short:   "Evaluate if a specific connection allowed",
	Aliases: []string{"eval", "check", "allow"}, // @etail - close on fewer, consider changing command name?

	// @etail: can this check be done in an Args function (e.g., incl. built-in's such as MinArgs(3))?
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
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
		destination := dstExternalIP
		if destination == "" {
			destination = destinationPod.String()
		}

		source := srcExternalIP
		if source == "" {
			source = sourcePod.String()
		}

		// @etail: add explicit logs to indicate progress (loading config, listing namespaces, ...)

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

		// @etail: use errors.Wrap for clearer error return?

		namespaces := []*corev1.Namespace{}
		nsNames := []string{sourcePod.Namespace, destinationPod.Namespace} // @etail: ok if same?
		for _, ns := range nsNames {
			n, apierr := clientset.CoreV1().Namespaces().Get(context.TODO(), ns, metav1.GetOptions{})
			if apierr != nil {
				return apierr
			}
			namespaces = append(namespaces, n)
		}

		pods := []*corev1.Pod{}
		podNames := []types.NamespacedName{sourcePod, destinationPod}
		for _, pod := range podNames {
			p, apierr := clientset.CoreV1().Pods(pod.Namespace).Get(context.TODO(), pod.Name, metav1.GetOptions{})
			if apierr != nil {
				return apierr
			}
			pods = append(pods, p)
		}

		policies := []*netv1.NetworkPolicy{}
		for _, ns := range nsNames {
			npList, apierr := clientset.NetworkingV1().NetworkPolicies(ns).List(context.TODO(), metav1.ListOptions{})
			if apierr != nil {
				return apierr
			}
			for i := range npList.Items {
				policies = append(policies, &npList.Items[i])
			}
		}

		pe := eval.NewPolicyEngine()

		if pe.SetResources(policies, pods, namespaces) != nil {
			return err
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
	// cluster access
	config := os.Getenv(clientcmd.RecommendedConfigPathEnvVar)
	if config == "" {
		config = clientcmd.RecommendedHomeFile
	}
	evaluateCmd.Flags().StringVarP(&kubeconfig, clientcmd.RecommendedConfigPathFlag, "k", config,
		"Path and file to use for kubeconfig when evaluating connections in a live cluster")
	evaluateCmd.Flags().StringVarP(&kubecontext, clientcmd.FlagContext, "c", "",
		"Kubernetes context to use when evaluating connections in a live cluster")
}
