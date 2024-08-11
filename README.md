# netpol-analyzer

## About netpol-analyzer
This repo contains a Golang library and CLI for analyzing k8s connectivity-configuration resources (a.k.a. network policies).


## CLI usage 

### Evaluate command
```
Evaluate if a specific connection allowed

Usage:
  k8snetpolicy evaluate [flags]

Aliases:
  evaluate, eval, check, allow

Examples:
  # Evaluate if a specific connection is allowed on given resources from dir path
  k8snetpolicy eval --dirpath ./resources_dir/ -s pod-1 -d pod-2 -p 80

  # Evaluate if a specific connection is allowed on a live k8s cluster
  k8snetpolicy eval -k ./kube/config -s pod-1 -d pod-2 -p 80

Flags:
      --destination-ip string          Destination (external) IP address
      --destination-namespace string   Destination pod namespace (default "default")
  -d, --destination-pod string         Destination pod name
  -p, --destination-port string        Destination port (name or number)
  -h, --help                           help for evaluate
      --protocol string                Protocol in use (tcp, udp, sctp) (default "tcp")
      --source-ip string               Source (external) IP address
  -n, --source-namespace string        Source pod namespace (default "default")
  -s, --source-pod string              Source pod name, required

Global Flags:
  -c, --context string      Kubernetes context to use when evaluating connections in a live cluster
      --dirpath string      Resources dir path when evaluating connections from a dir
      --fail                fail on the first encountered error
      --include-json        consider JSON manifests (in addition to YAML) when analyzing from dir
  -k, --kubeconfig string   Path and file to use for kubeconfig when evaluating connections in a live cluster
  -q, --quiet               Runs quietly, reports only severe errors and results
  -v, --verbose             Runs with more informative messages printed to log
```

### List command
```
Lists all allowed connections based on the workloads, network policies, and Ingress/Route resources defined.

Connections between workload to itself are excluded from the output.

Usage:
  k8snetpolicy list [flags]

Examples:
  # Get list of allowed connections from resources dir path
  k8snetpolicy list --dirpath ./resources_dir/

  # Get list of allowed connections from live k8s cluster
  k8snetpolicy list -k ./kube/config

Flags:
      --exposure               Enhance the analysis of permitted connectivity with exposure analysis
  -f, --file string            Write output to specified file
      --focusworkload string   Focus connections of specified workload in the output (<workload-name> or <workload-namespace/workload-name>)
  -h, --help                   help for list
  -o, --output string          Required output format (txt,json,dot,csv,md) (default "txt")

Global Flags:
  -c, --context string      Kubernetes context to use when evaluating connections in a live cluster
      --dirpath string      Resources dir path when evaluating connections from a dir
      --fail                fail on the first encountered error
  -k, --kubeconfig string   Path and file to use for kubeconfig when evaluating connections in a live cluster (default "C:\\Users\\847978756\\.kube\\config")
  -q, --quiet               runs quietly, reports only severe errors and results
  -v, --verbose             runs with more informative messages printed to log
```

### Diff command
```
Reports all differences in allowed connections between two different directories of YAML manifests.

Usage:
  k8snetpolicy diff [flags]

Examples:
  # Get list of different allowed connections between two resources dir paths
  k8snetpolicy diff --dir1 ./resources_dir/ --dir2 ./other_resources_dir/

Flags:
      --dir1  string  First resources dir path
      --dir2  string  Second resources dir path to be compared with the first dir path
  -f, --file string            Write output to specified file
  -o, --output string Required output format (txt, csv, md, dot) (default "txt")  
  -h, --help   help for diff

Global Flags:
  -c, --context string      Kubernetes context to use when evaluating connections in a live cluster
      --dirpath string      Resources dir path when evaluating connections from a dir
      --fail                fail on the first encountered error
      --include-json        consider JSON manifests (in addition to YAML) when analyzing from dir
  -k, --kubeconfig string   Path and file to use for kubeconfig when evaluating connections in a live cluster
  -q, --quiet               Runs quietly, reports only severe errors and results
  -v, --verbose             Runs with more informative messages printed to log  
```

### Example outputs:

```
$ k8snetpolicy eval --dirpath tests/onlineboutique -s adservice-77d5cd745d-t8mx4 -d emailservice-54c7c5d9d-vp27n -p 80

default/adservice-77d5cd745d-t8mx4 => default/emailservice-54c7c5d9d-vp27n over tcp/80: false



$ k8snetpolicy list --dirpath tests/onlineboutique_workloads

0.0.0.0-255.255.255.255 => default/redis-cart[Deployment] : All Connections
default/checkoutservice[Deployment] => default/cartservice[Deployment] : TCP 7070
default/checkoutservice[Deployment] => default/currencyservice[Deployment] : TCP 7000
default/checkoutservice[Deployment] => default/emailservice[Deployment] : TCP 8080
default/checkoutservice[Deployment] => default/paymentservice[Deployment] : TCP 50051
default/checkoutservice[Deployment] => default/productcatalogservice[Deployment] : TCP 3550
default/checkoutservice[Deployment] => default/shippingservice[Deployment] : TCP 50051
default/frontend[Deployment] => default/adservice[Deployment] : TCP 9555
default/frontend[Deployment] => default/cartservice[Deployment] : TCP 7070
default/frontend[Deployment] => default/checkoutservice[Deployment] : TCP 5050
default/frontend[Deployment] => default/currencyservice[Deployment] : TCP 7000
default/frontend[Deployment] => default/productcatalogservice[Deployment] : TCP 3550
default/frontend[Deployment] => default/recommendationservice[Deployment] : TCP 8080
default/frontend[Deployment] => default/shippingservice[Deployment] : TCP 50051
default/loadgenerator[Deployment] => default/frontend[Deployment] : TCP 8080
default/recommendationservice[Deployment] => default/productcatalogservice[Deployment] : TCP 3550
default/redis-cart[Deployment] => 0.0.0.0-255.255.255.255 : All Connections



$ ./bin/k8snetpolicy diff --dir1 tests/onlineboutique_workloads --dir2 tests/onlineboutique_workloads_changed_netpols
Connectivity diff:
source: default/checkoutservice[Deployment], destination: default/cartservice[Deployment], dir1:  TCP 7070, dir2: TCP 8000, diff-type: changed
source: default/checkoutservice[Deployment], destination: default/emailservice[Deployment], dir1:  TCP 8080, dir2: TCP 8080,9555, diff-type: changed
source: default/cartservice[Deployment], destination: default/emailservice[Deployment], dir1:  No Connections, dir2: TCP 9555, diff-type: added
source: default/checkoutservice[Deployment], destination: default/adservice[Deployment], dir1:  No Connections, dir2: TCP 9555, diff-type: added
source: 128.0.0.0-255.255.255.255, destination: default/redis-cart[Deployment], dir1:  All Connections, dir2: No Connections, diff-type: removed
source: default/checkoutservice[Deployment], destination: default/currencyservice[Deployment], dir1:  TCP 7000, dir2: No Connections, diff-type: removed
source: default/frontend[Deployment], destination: default/adservice[Deployment], dir1:  TCP 9555, dir2: No Connections, diff-type: removed
source: default/redis-cart[Deployment], destination: 0.0.0.0-255.255.255.255, dir1:  All Connections, dir2: No Connections, diff-type: removed


```

Additional details about the connectivity analysis and its output is specified [here](docs/connlist_output.md).

Additional details about exposure analysis (`--exposure` flag for the `list` command) is specified [here](docs/exposure_analysis.md).

Additional details about the connectivity diff command and its output is specified [here](docs/diff_output.md).

## Build the project

Make sure you have golang 1.21+ on your platform

```commandline
git clone git@github.com:np-guard/netpol-analyzer.git
cd netpol-analyzer
make mod 
make build
```

Test your build by running `./bin/k8snetpolicy -h`.



