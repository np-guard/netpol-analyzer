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
	"github.com/np-guard/netpol-analyzer/pkg/netpol/logger"
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

func validateEvalFlags() error {
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
}

func updatePolicyEngineObjectsFromDirPath(pe *eval.PolicyEngine, podNames []types.NamespacedName) error {
	// get relevant resources from dir path
	scanner := scan.NewResourcesScanner(logger.NewDefaultLogger(), false, filepath.WalkDir)
	objectsList, processingErrs := scanner.FilesToObjectsListFiltered(dirPath, podNames)
	for _, err := range processingErrs {
		if err.IsFatal() || err.IsSevere() {
			return fmt.Errorf("scan dir path %s had processing errors: %v", dirPath, err.Error())
		}
	}

	var err error
	for _, obj := range objectsList {
		switch obj.Kind {
		case scan.Pod:
			err = pe.UpsertObject(obj.Pod)
		case scan.Namespace:
			err = pe.UpsertObject(obj.Namespace)
		case scan.Networkpolicy:
			err = pe.UpsertObject(obj.Networkpolicy)
		case scan.Service:
			err = pe.UpsertObject(obj.Service)
		default:
			continue
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func updatePolicyEngineObjectsFromLiveCluster(pe *eval.PolicyEngine, podNames []types.NamespacedName, nsNames []string) error {
	// get relevant resources from k8s live cluster
	const ctxTimeoutSeconds = 3
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeoutSeconds*time.Second)
	defer cancel()

	for _, name := range nsNames {
		ns, apierr := clientset.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
		if apierr != nil {
			return apierr
		}
		if err := pe.UpsertObject(ns); err != nil {
			return err
		}
	}

	for _, name := range podNames {
		pod, apierr := clientset.CoreV1().Pods(name.Namespace).Get(ctx, name.Name, metav1.GetOptions{})
		if apierr != nil {
			return apierr
		}
		if err := pe.UpsertObject(pod); err != nil {
			return err
		}
	}

	for _, ns := range nsNames {
		npList, apierr := clientset.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
		if apierr != nil {
			return apierr
		}
		for i := range npList.Items {
			if err := pe.UpsertObject(&npList.Items[i]); err != nil {
				return err
			}
		}
	}
	return nil
}

func runEvalCommand() error {
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
		if err := updatePolicyEngineObjectsFromDirPath(pe, podNames); err != nil {
			return err
		}
	} else {
		if err := updatePolicyEngineObjectsFromLiveCluster(pe, podNames, nsNames); err != nil {
			return err
		}
	}

	allowed, err := pe.CheckIfAllowed(source, destination, protocol, port)
	if err != nil {
		return err
	}

	// @todo: use a logger instead?
	fmt.Printf("%v => %v over %s/%s: %t\n", source, destination, protocol, port, allowed)
	return nil
}

// newCommandEvaluate returns a cobra command with the appropriate configuration and flags to run evaluate command
func newCommandEvaluate() *cobra.Command {
	c := &cobra.Command{
		Use:     "evaluate",
		Short:   "Evaluate if a specific connection allowed",
		Aliases: []string{"eval", "check", "allow"}, // TODO: close on fewer, consider changing command name?
		Example: `  # Evaluate if a specific connection is allowed on given resources from dir path
	k8snetpolicy eval --dirpath ./resources_dir/ -s pod-1 -d pod-2 -p 80
	
	# Evaluate if a specific connection is allowed on a live k8s cluster
	k8snetpolicy eval -k ./kube/config -s pod-1 -d pod-2 -p 80`,

		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := validateEvalFlags(); err != nil {
				return err
			}
			// call parent pre-run
			if parent := cmd.Parent(); parent != nil {
				if parent.PersistentPreRunE != nil {
					if err := parent.PersistentPreRunE(cmd, args); err != nil {
						return err
					}
				}
			}
			return nil
		},

		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runEvalCommand(); err != nil {
				return err
			}
			return nil
		},
	}

	// add flags
	c.Flags().StringVarP(&sourcePod.Name, "source-pod", "s", sourcePod.Name, "Source pod name, required")
	c.Flags().StringVarP(&sourcePod.Namespace, "source-namespace", "n", sourcePod.Namespace, "Source pod namespace")
	c.Flags().StringVarP(&destinationPod.Name, "destination-pod", "d", destinationPod.Name, "Destination pod name")
	c.Flags().StringVarP(&destinationPod.Namespace, "destination-namespace", "", destinationPod.Namespace, "Destination pod namespace")
	c.Flags().StringVarP(&srcExternalIP, "source-ip", "", srcExternalIP, "Source (external) IP address")
	c.Flags().StringVarP(&dstExternalIP, "destination-ip", "", dstExternalIP, "Destination (external) IP address")
	c.Flags().StringVarP(&port, "destination-port", "p", port, "Destination port (name or number)")
	c.Flags().StringVarP(&protocol, "protocol", "", protocol, "Protocol in use (tcp, udp, sctp)")

	return c
}
