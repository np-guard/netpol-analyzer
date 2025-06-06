/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	"github.com/np-guard/netpol-analyzer/pkg/internal/common"
	"github.com/np-guard/netpol-analyzer/pkg/internal/netpolerrors"
	"github.com/np-guard/netpol-analyzer/pkg/logger"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/fsscanner"
	"github.com/np-guard/netpol-analyzer/pkg/manifests/parser"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
)

// TODO: consider using k8s.io/cli-runtime/pkg/genericclioptions to load kube config.
// 		Currently adds many options flags, so wait until cobra supports something
// 		like NamedFlagSet's.

const (
	defaultNs = metav1.NamespaceDefault
)

var (
	// evaluated connection information
	defaultProtocol = strings.ToLower(string(v1.ProtocolTCP))
	protocol        = defaultProtocol
	sourcePod       = types.NamespacedName{Namespace: defaultNs}
	destinationPod  = types.NamespacedName{Namespace: defaultNs}
	srcExternalIP   string
	dstExternalIP   string
	port            string
)

func validateEvalFlags() error {
	// Validate flags values
	if sourcePod.Name == "" && srcExternalIP == "" {
		return errors.New(netpolerrors.NoSourceDefinedErr)
	} else if sourcePod.Name != "" && srcExternalIP != "" {
		return errors.New(netpolerrors.OnlyOneSrcFlagErrStr)
	}

	if destinationPod.Name == "" && dstExternalIP == "" {
		return errors.New(netpolerrors.NoDestDefinedErr)
	} else if destinationPod.Name != "" && dstExternalIP != "" {
		return errors.New(netpolerrors.OnlyOneDstFlagErrStr)
	}

	if srcExternalIP != "" && dstExternalIP == "" {
		return errors.New(netpolerrors.OnlyOneIPPeerErrStr)
	}

	if port == "" {
		return errors.New(netpolerrors.RequiredDstPortFlagErr)
	}
	return nil
}

//gocyclo:ignore
func updatePolicyEngineObjectsFromDirPath(pe *eval.PolicyEngine, podNames []types.NamespacedName) error {
	// get relevant resources from dir path
	eLogger := logger.NewDefaultLoggerWithVerbosity(determineLogVerbosity())

	rList, errs := fsscanner.GetResourceInfosFromDirPath([]string{dirPath}, true, false)
	if errs != nil {
		// TODO: consider avoid logging this error because it is already printed to log by the builder
		if len(rList) == 0 || stopOnFirstError {
			err := utilerrors.NewAggregate(errs)
			eLogger.Errorf(err, netpolerrors.ErrGettingResInfoFromDir)
			return err // return as fatal error if rList is empty or if stopOnError is on
		}
		// split err if it's an aggregated error to a list of separate errors
		for _, err := range errs {
			eLogger.Errorf(err, netpolerrors.FailedReadingFileErrorStr) // print to log the error from builder
		}
	}
	objectsList, processingErrs := parser.ResourceInfoListToK8sObjectsList(rList, eLogger, false)
	for _, err := range processingErrs {
		if err.IsFatal() || (stopOnFirstError && err.IsSevere()) {
			return fmt.Errorf("scan dir path %s had processing errors: %w", dirPath, err.Error())
		}
	}
	objectsList = parser.FilterObjectsList(objectsList, podNames)

	// first add namespaces - so in case there are UDN objects in the resources, will be handled correctly
	err := pe.InsertNamespacesFromResources(objectsList)
	if err != nil {
		return err
	}
	for i := range objectsList {
		obj := objectsList[i]
		switch obj.Kind {
		case parser.Pod:
			err = pe.InsertObject(obj.Pod)
		case parser.Namespace: // already inserted
			continue
			// netpols kinds
		case parser.NetworkPolicy:
			err = pe.InsertObject(obj.NetworkPolicy)
		case parser.AdminNetworkPolicy:
			err = pe.InsertObject(obj.AdminNetworkPolicy)
		case parser.BaselineAdminNetworkPolicy:
			err = pe.InsertObject(obj.BaselineAdminNetworkPolicy)
		case parser.UserDefinedNetwork:
			err = pe.InsertObject(obj.UserDefinedNetwork)
		case parser.ClusterUserDefinedNetwork:
			err = pe.InsertObject(obj.ClusterUserDefinedNetwork)
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
	// get command's relevant pods, namespaces and policies
	err := updatePolicyEngineWithBasicK8sObjects(pe, podNames, nsNames)
	if err != nil {
		return err
	}
	// update the policy engine with (B)ANPs
	return pe.UpdatePolicyEngineWithK8sPolicyAPIObjects(policyAPIClientset)
}

func updatePolicyEngineWithBasicK8sObjects(pe *eval.PolicyEngine, podNames []types.NamespacedName, nsNames []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), common.CtxTimeoutSeconds*time.Second)
	defer cancel()

	for _, name := range nsNames {
		ns, apiErr := clientset.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
		if apiErr != nil {
			return apiErr
		}
		if err := pe.InsertObject(ns); err != nil {
			return err
		}
	}

	for _, name := range podNames {
		pod, apiErr := clientset.CoreV1().Pods(name.Namespace).Get(ctx, name.Name, metav1.GetOptions{})
		if apiErr != nil {
			return apiErr
		}
		if err := pe.InsertObject(pod); err != nil {
			return err
		}
	}

	for _, ns := range nsNames {
		npList, apiErr := clientset.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
		if apiErr != nil {
			return apiErr
		}
		for i := range npList.Items {
			if err := pe.InsertObject(&npList.Items[i]); err != nil {
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

	cLogger := logger.NewDefaultLoggerWithVerbosity(determineLogVerbosity())
	pe, err := eval.NewPolicyEngineWithOptionsList(eval.WithLogger(cLogger))
	if err != nil { // will not get here
		return err
	}

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
	netpol-analyzer eval --dirpath ./resources_dir/ -s pod-1 -d pod-2 -p 80
	
	# Evaluate if a specific connection is allowed on a live k8s cluster
	netpol-analyzer eval -k ./kube/config -s pod-1 -d pod-2 -p 80`,

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
				cmd.SilenceUsage = true // don't print usage message when returning an error from running a valid command
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
