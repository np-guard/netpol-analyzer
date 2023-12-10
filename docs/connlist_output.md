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

`list` output in `txt` format:
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

`list` output in `md` format:
```
./bin/k8snetpolicy list --dirpath tests/demo_app_with_routes_and_ingress/ -o md
```
| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255 | helloworld/hello-world[Deployment] | All Connections |
| 0.0.0.0-255.255.255.255 | ingressworld/ingress-world[Deployment] | All Connections |
| 0.0.0.0-255.255.255.255 | routeworld/route-world[Deployment] | All Connections |
| helloworld/hello-world[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| helloworld/hello-world[Deployment] | ingressworld/ingress-world[Deployment] | All Connections |
| helloworld/hello-world[Deployment] | routeworld/route-world[Deployment] | All Connections |
| ingressworld/ingress-world[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| ingressworld/ingress-world[Deployment] | helloworld/hello-world[Deployment] | All Connections |
| ingressworld/ingress-world[Deployment] | routeworld/route-world[Deployment] | All Connections |
| routeworld/route-world[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| routeworld/route-world[Deployment] | helloworld/hello-world[Deployment] | All Connections |
| routeworld/route-world[Deployment] | ingressworld/ingress-world[Deployment] | All Connections |
| {ingress-controller} | helloworld/hello-world[Deployment] | TCP 8000 |
| {ingress-controller} | ingressworld/ingress-world[Deployment] | TCP 8090 |
| {ingress-controller} | routeworld/route-world[Deployment] | TCP 8060 |

`list` output in `csv` format:
```
./bin/k8snetpolicy list --dirpath tests/demo_app_with_routes_and_ingress/ -o csv

src,dst,conn
0.0.0.0-255.255.255.255,helloworld/hello-world[Deployment],All Connections
0.0.0.0-255.255.255.255,ingressworld/ingress-world[Deployment],All Connections
0.0.0.0-255.255.255.255,routeworld/route-world[Deployment],All Connections
helloworld/hello-world[Deployment],0.0.0.0-255.255.255.255,All Connections
helloworld/hello-world[Deployment],ingressworld/ingress-world[Deployment],All Connections
helloworld/hello-world[Deployment],routeworld/route-world[Deployment],All Connections
ingressworld/ingress-world[Deployment],0.0.0.0-255.255.255.255,All Connections
ingressworld/ingress-world[Deployment],helloworld/hello-world[Deployment],All Connections
ingressworld/ingress-world[Deployment],routeworld/route-world[Deployment],All Connections
routeworld/route-world[Deployment],0.0.0.0-255.255.255.255,All Connections
routeworld/route-world[Deployment],helloworld/hello-world[Deployment],All Connections
routeworld/route-world[Deployment],ingressworld/ingress-world[Deployment],All Connections
{ingress-controller},helloworld/hello-world[Deployment],TCP 8000
{ingress-controller},ingressworld/ingress-world[Deployment],TCP 8090
{ingress-controller},routeworld/route-world[Deployment],TCP 8060
```

`list` output in `json` format:
```
./bin/k8snetpolicy list --dirpath tests/demo_app_with_routes_and_ingress/ -o json

[
  {
    "src": "0.0.0.0-255.255.255.255",
    "dst": "helloworld/hello-world[Deployment]",
    "conn": "All Connections"
  },
  {
    "src": "0.0.0.0-255.255.255.255",
    "dst": "ingressworld/ingress-world[Deployment]",
    "conn": "All Connections"
  },
  {
    "src": "0.0.0.0-255.255.255.255",
    "dst": "routeworld/route-world[Deployment]",
    "conn": "All Connections"
  },
  {
    "src": "helloworld/hello-world[Deployment]",
    "dst": "0.0.0.0-255.255.255.255",
    "conn": "All Connections"
  },
  {
    "src": "helloworld/hello-world[Deployment]",
    "dst": "ingressworld/ingress-world[Deployment]",
    "conn": "All Connections"
  },
  {
    "src": "helloworld/hello-world[Deployment]",
    "dst": "routeworld/route-world[Deployment]",
    "conn": "All Connections"
  },
  {
    "src": "ingressworld/ingress-world[Deployment]",
    "dst": "0.0.0.0-255.255.255.255",
    "conn": "All Connections"
  },
  {
    "src": "ingressworld/ingress-world[Deployment]",
    "dst": "helloworld/hello-world[Deployment]",
    "conn": "All Connections"
  },
  {
    "src": "ingressworld/ingress-world[Deployment]",
    "dst": "routeworld/route-world[Deployment]",
    "conn": "All Connections"
  },
  {
    "src": "routeworld/route-world[Deployment]",
    "dst": "0.0.0.0-255.255.255.255",
    "conn": "All Connections"
  },
  {
    "src": "routeworld/route-world[Deployment]",
    "dst": "helloworld/hello-world[Deployment]",
    "conn": "All Connections"
  },
  {
    "src": "routeworld/route-world[Deployment]",
    "dst": "ingressworld/ingress-world[Deployment]",
    "conn": "All Connections"
  },
  {
    "src": "{ingress-controller}",
    "dst": "helloworld/hello-world[Deployment]",
    "conn": "TCP 8000"
  },
  {
    "src": "{ingress-controller}",
    "dst": "ingressworld/ingress-world[Deployment]",
    "conn": "TCP 8090"
  },
  {
    "src": "{ingress-controller}",
    "dst": "routeworld/route-world[Deployment]",
    "conn": "TCP 8060"
  }
]
```

`list` output in `dot` format:

in `dot` output graphs, all the peers of the analyzed cluster are grouped by their namespaces.
```
./bin/k8snetpolicy list --dirpath tests/demo_app_with_routes_and_ingress/ -o dot

digraph {
        subgraph cluster_helloworld {
                "helloworld/hello-world[Deployment]" [label="hello-world[Deployment]" color="blue" fontcolor="blue"]
                label="helloworld"
        }
        subgraph cluster_ingressworld {
                "ingressworld/ingress-world[Deployment]" [label="ingress-world[Deployment]" color="blue" fontcolor="blue"]
                label="ingressworld"
        }
        subgraph cluster_routeworld {
                "routeworld/route-world[Deployment]" [label="route-world[Deployment]" color="blue" fontcolor="blue"]
                label="routeworld"
        }
        "0.0.0.0-255.255.255.255" [label="0.0.0.0-255.255.255.255" color="red2" fontcolor="red2"]
        "{ingress-controller}" [label="{ingress-controller}" color="blue" fontcolor="blue"]
        "0.0.0.0-255.255.255.255" -> "helloworld/hello-world[Deployment]" [label="All Connections" color="gold2" fontcolor="darkgreen"]
        "0.0.0.0-255.255.255.255" -> "ingressworld/ingress-world[Deployment]" [label="All Connections" color="gold2" fontcolor="darkgreen"]
        "0.0.0.0-255.255.255.255" -> "routeworld/route-world[Deployment]" [label="All Connections" color="gold2" fontcolor="darkgreen"]
        "helloworld/hello-world[Deployment]" -> "0.0.0.0-255.255.255.255" [label="All Connections" color="gold2" fontcolor="darkgreen"]
        "helloworld/hello-world[Deployment]" -> "ingressworld/ingress-world[Deployment]" [label="All Connections" color="gold2" fontcolor="darkgreen"]
        "helloworld/hello-world[Deployment]" -> "routeworld/route-world[Deployment]" [label="All Connections" color="gold2" fontcolor="darkgreen"]
        "ingressworld/ingress-world[Deployment]" -> "0.0.0.0-255.255.255.255" [label="All Connections" color="gold2" fontcolor="darkgreen"]
        "ingressworld/ingress-world[Deployment]" -> "helloworld/hello-world[Deployment]" [label="All Connections" color="gold2" fontcolor="darkgreen"]
        "ingressworld/ingress-world[Deployment]" -> "routeworld/route-world[Deployment]" [label="All Connections" color="gold2" fontcolor="darkgreen"]
        "routeworld/route-world[Deployment]" -> "0.0.0.0-255.255.255.255" [label="All Connections" color="gold2" fontcolor="darkgreen"]
        "routeworld/route-world[Deployment]" -> "helloworld/hello-world[Deployment]" [label="All Connections" color="gold2" fontcolor="darkgreen"]
        "routeworld/route-world[Deployment]" -> "ingressworld/ingress-world[Deployment]" [label="All Connections" color="gold2" fontcolor="darkgreen"]
        "{ingress-controller}" -> "helloworld/hello-world[Deployment]" [label="TCP 8000" color="gold2" fontcolor="darkgreen"]
        "{ingress-controller}" -> "ingressworld/ingress-world[Deployment]" [label="TCP 8090" color="gold2" fontcolor="darkgreen"]
        "{ingress-controller}" -> "routeworld/route-world[Deployment]" [label="TCP 8060" color="gold2" fontcolor="darkgreen"]
}
```

`svg` graph from `dot` format output can be produced using `graphviz` as following:
```
dot -Tsvg test_outputs/connlist/demo_app_with_routes_and_ingress_connlist_output.dot -o test_outputs/connlist/demo_app_with_routes_and_ingress_connlist_output.dot.svg
```
Reminder: frames in the graph represent namespaces of the analyzed cluster

![svg graph](./connlist_example_svg.svg)


### Possible warning
`Route/Ingress specified workload as a backend, but network policies are blocking ingress connections from an arbitrary in-cluster source to this workload. Connectivity map will not include a possibly allowed connection between the ingress controller and this workload.`

Since the analysis assumes the manifest of the ingress controller is unknown, it checks whether an arbitrary workload can access the destination workloads specified in Ingress/Route rules. If such access is not permitted by network policies, this connection is removed from the report. It may be an allowed connection if a network policy specifically allows ingress access to that workload from a specific workload/namespace of the actual ingress controller installed.
