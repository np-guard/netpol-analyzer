# List command - connectivity analysis output

Resource manifests considered for a connectivity analysis:
- workload resources (such as Kubernetes Pod / Deployment)
- Kubernetes NetworkPolicy
- Kubernetes Ingress
- Openshift Route

The connectivity output consists of lines of the form: `src` => `dst` : `connections`

For connections inferred from network policy resources only, the `src` and `dst` are workloads or external IP-blocks.

For Ingress/Route analysis, the `src` is specified as `{ingress-controller}`, representing the cluster's ingress controller Pod.
Its connectivity lines are of the form: `{ingress-controller}` => `dst` : `connections`, where `dst` is a workload in the cluster.
This analysis is currently activated only with `--dir-path` flag, and not on a live cluster.
It assumes that the ingress controller Pod is unknown, and thus using this notation of `{ingress-controller}`.


## Example Output

```
$ ./bin/k8snetpolicy list --dirpath tests/demo_app_with_routes_and_ingress/

0.0.0.0-255.255.255.255 => helloworld/hello-world[Deployment] : All Connections
0.0.0.0-255.255.255.255 => ingressworld/ingress-world[Deployment] : All Connections
0.0.0.0-255.255.255.255 => routeworld/route-world[Deployment] : All Connections
helloworld/hello-world[Deployment] => 0.0.0.0-255.255.255.255 : All Connections
helloworld/hello-world[Deployment] => ingressworld/ingress-world[Deployment] : All Connections
helloworld/hello-world[Deployment] => routeworld/route-world[Deployment] : All Connections
ingressworld/ingress-world[Deployment] => 0.0.0.0-255.255.255.255 : All Connections
ingressworld/ingress-world[Deployment] => helloworld/hello-world[Deployment] : All Connections
ingressworld/ingress-world[Deployment] => routeworld/route-world[Deployment] : All Connections
routeworld/route-world[Deployment] => 0.0.0.0-255.255.255.255 : All Connections
routeworld/route-world[Deployment] => helloworld/hello-world[Deployment] : All Connections
routeworld/route-world[Deployment] => ingressworld/ingress-world[Deployment] : All Connections
{ingress-controller} => helloworld/hello-world[Deployment] : TCP 8000
{ingress-controller} => ingressworld/ingress-world[Deployment] : TCP 8090
{ingress-controller} => routeworld/route-world[Deployment] : TCP 8060

```

### Possible warning
`Route/Ingress specified workload as a backend, but network policies are blocking ingress connections from an arbitrary in-cluster source to this workload. Connectivity map will not include a possibly allowed connection between the ingress controller and this workload.`

Since the analysis assumes the manifest of the ingress controller is unknown, it checks whether an arbitrary workload can access the destination workloads specified in Ingress/Route rules. If such access is not permitted by network policies, this connection is removed from the report. It may be an allowed connection if a network policy specifically allows ingress access to that workload from a specific workload/namespace of the actual ingress controller installed.
