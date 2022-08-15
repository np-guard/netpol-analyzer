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
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"
	"k8s.io/apimachinery/pkg/types"
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

// @todo enable subcommands using github.com/spf13/Cobra?

func main() {
	flag.StringVar(&sourcePod.Name, "pod", sourcePod.Name, "source pod name, required")
	flag.StringVar(&sourcePod.Namespace, "namespace", sourcePod.Namespace, "source pod namespace")
	flag.StringVar(&targetPod.Name, "target-pod", targetPod.Name, "destination pod name")
	flag.StringVar(&targetPod.Namespace, "target-namespace", targetPod.Namespace, "destination pod namespace")
	flag.StringVar(&srcExternalIP, "source-ip", srcExternalIP, "source (external) IP")
	flag.StringVar(&dstExternalIP, "target-ip", dstExternalIP, "destination (external) IP")
	flag.StringVar(&port, "port", port, "destination port (name or number)")
	flag.StringVar(&protocol, "protocol", protocol, "protocol in use (tcp, udp, sctp)")
	flag.BoolVar(&help, "help", false, "display help")

	flag.Parse()
	err := validateFlags()

	if help || err != nil {
		usage(err)
	}

	destination := dstExternalIP
	if destination == "" {
		destination = targetPod.String()
	}
	source := srcExternalIP
	if source == "" {
		source = sourcePod.String()
	}
	fmt.Printf("%v", destination)
	fmt.Printf("%v", source)

	eval.CheckIfAllowed(source, destination, protocol, port)
}

func usage(err error) {
	if err != nil {
		fmt.Println(err)
	}
	flag.Usage()
	if err != nil {
		os.Exit(-1)
	}
}

func validateFlags() error {
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
}
