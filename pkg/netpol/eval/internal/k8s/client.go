// Copyright 2022
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package k8s

package k8s

import (
	"flag"
	"os"
	"strings"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

// abstracts the differences between an in-cluster and out-of-cluster
// client configuration.

// New returns a new k8s client interface.
// It resolves whether it is running inside a k8s cluster or not.
// When running out of cluster, it'll attempt to load the default kubeconfig file (or an explicit
// config path if provided)
func New() (*kubernetes.Clientset, error) {
	config, err := Config()

	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(config)
}

// Config returns a k8s REST configuration (in cluster or external)
func Config() (*rest.Config, error) {
	var config *rest.Config
	var err error
	if _, inCluster := os.LookupEnv("KUBERNETES_SERVICE_HOST"); inCluster {
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, err
		}
	} else {
		defaultKubeConfigPath := ""

		if defaultKubeConfigPath = os.Getenv(clientcmd.RecommendedConfigPathEnvVar); defaultKubeConfigPath == "" {
			if homedir.HomeDir() != "" {
				defaultKubeConfigPath = clientcmd.RecommendedHomeFile
			}
		}
		kubeconfig := flag.String(clientcmd.RecommendedConfigPathFlag, defaultKubeConfigPath, "path to the kubeconfig file")
		flag.Parse()
		config, err = clientcmd.BuildConfigFromFlags("", *kubeconfig)
		if err != nil {
			return nil, err
		}
	}
	return config, err
}

// Namespace returns the Pod namespace, either from environment or k8s files
func PodNamespace() (string, error) {
	const nsFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
		return ns, nil
	}
	if data, err := os.ReadFile(nsFile); err == nil {
		if ns := strings.TrimSpace(string(data)); len(ns) > 0 {
			return ns, nil
		}
		return "", err
	}
	return "", nil
}
