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
  -k, --kubeconfig string   Path and file to use for kubeconfig when evaluating connections in a live cluster (default "/home/adisos/.kube/config")
```

### List command
```
Lists all allowed connections based on the workloads and network policies
defined

Usage:
  k8snetpolicy list [flags]

Examples:
  # Get list of allowed connections from resources dir path
  k8snetpolicy list --dirpath ./resources_dir/

  # Get list of allowed connections from live k8s cluster
  k8snetpolicy list -k ./kube/config

Flags:
  -h, --help   help for list

Global Flags:
  -c, --context string      Kubernetes context to use when evaluating connections in a live cluster
      --dirpath string      Resources dir path when evaluating connections from a dir
  -k, --kubeconfig string   Path and file to use for kubeconfig when evaluating connections in a live cluster (default "/home/adisos/.kube/config")
```



## Example outputs:
```
$ k8snetpolicy eval --dirpath tests/onlineboutique -s adservice-77d5cd745d-t8mx4 -d emailservice-54c7c5d9d-vp27n -p 80

default/adservice-77d5cd745d-t8mx4 => default/emailservice-54c7c5d9d-vp27n over tcp/80: false



$ k8snetpolicy list --dirpath tests/onlineboutique_workloads

0.0.0.0-255.255.255.255 => default/redis-cart[Deployment] : All Connections
default/adservice[Deployment] => default/adservice[Deployment] : All Connections
default/cartservice[Deployment] => default/cartservice[Deployment] : All Connections
default/checkoutservice[Deployment] => default/cartservice[Deployment] : TCP 7070
default/checkoutservice[Deployment] => default/checkoutservice[Deployment] : All Connections
default/checkoutservice[Deployment] => default/currencyservice[Deployment] : TCP 7000
default/checkoutservice[Deployment] => default/emailservice[Deployment] : TCP 8080
default/checkoutservice[Deployment] => default/paymentservice[Deployment] : TCP 50051
default/checkoutservice[Deployment] => default/productcatalogservice[Deployment] : TCP 3550
default/checkoutservice[Deployment] => default/shippingservice[Deployment] : TCP 50051
default/currencyservice[Deployment] => default/currencyservice[Deployment] : All Connections
default/emailservice[Deployment] => default/emailservice[Deployment] : All Connections
default/frontend[Deployment] => default/adservice[Deployment] : TCP 9555
default/frontend[Deployment] => default/cartservice[Deployment] : TCP 7070
default/frontend[Deployment] => default/checkoutservice[Deployment] : TCP 5050
default/frontend[Deployment] => default/currencyservice[Deployment] : TCP 7000
default/frontend[Deployment] => default/frontend[Deployment] : All Connections
default/frontend[Deployment] => default/productcatalogservice[Deployment] : TCP 3550
default/frontend[Deployment] => default/recommendationservice[Deployment] : TCP 8080
default/frontend[Deployment] => default/shippingservice[Deployment] : TCP 50051
default/loadgenerator[Deployment] => default/frontend[Deployment] : TCP 8080
default/paymentservice[Deployment] => default/paymentservice[Deployment] : All Connections
default/productcatalogservice[Deployment] => default/productcatalogservice[Deployment] : All Connections
default/recommendationservice[Deployment] => default/productcatalogservice[Deployment] : TCP 3550
default/recommendationservice[Deployment] => default/recommendationservice[Deployment] : All Connections
default/redis-cart[Deployment] => 0.0.0.0-255.255.255.255 : All Connections
default/redis-cart[Deployment] => default/redis-cart[Deployment] : All Connections
default/shippingservice[Deployment] => default/shippingservice[Deployment] : All Connections

```

## Build the project

Make sure you have golang 1.18+ on your platform

```commandline
git clone git@github.com:np-guard/netpol-analyzer.git
cd netpol-analyzer
make mod 
make build
```



