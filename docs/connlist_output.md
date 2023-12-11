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
$ ./bin/k8snetpolicy list --dirpath tests/netpol-analysis-example-minimal/

0.0.0.0-255.255.255.255 => default/frontend[Deployment] : TCP 8080
default/frontend[Deployment] => 0.0.0.0-255.255.255.255 : UDP 53
default/frontend[Deployment] => default/backend[Deployment] : TCP 9090
```

`list` output in `md` format:
```
./bin/k8snetpolicy list --dirpath tests/netpol-analysis-example-minimal/ -o md
```
| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255 | default/frontend[Deployment] | TCP 8080 |
| default/frontend[Deployment] | 0.0.0.0-255.255.255.255 | UDP 53 |
| default/frontend[Deployment] | default/backend[Deployment] | TCP 9090 |

`list` output in `csv` format:
```
./bin/k8snetpolicy list --dirpath tests/netpol-analysis-example-minimal/ -o csv

src,dst,conn
0.0.0.0-255.255.255.255,default/frontend[Deployment],TCP 8080
default/frontend[Deployment],0.0.0.0-255.255.255.255,UDP 53
default/frontend[Deployment],default/backend[Deployment],TCP 9090
```

`list` output in `json` format:
```
./bin/k8snetpolicy list --dirpath tests/netpol-analysis-example-minimal/ -o json

[
  {
    "src": "0.0.0.0-255.255.255.255",
    "dst": "default/frontend[Deployment]",
    "conn": "TCP 8080"
  },
  {
    "src": "default/frontend[Deployment]",
    "dst": "0.0.0.0-255.255.255.255",
    "conn": "UDP 53"
  },
  {
    "src": "default/frontend[Deployment]",
    "dst": "default/backend[Deployment]",
    "conn": "TCP 9090"
  }
]
```

`list` output in `dot` format:

In `dot` output graphs, all the peers of the analyzed cluster are grouped by their namespaces.
```
./bin/k8snetpolicy list --dirpath tests/netpol-analysis-example-minimal/ -o dot

digraph {
	subgraph cluster_default {
		"default/backend[Deployment]" [label="backend[Deployment]" color="blue" fontcolor="blue"]
		"default/frontend[Deployment]" [label="frontend[Deployment]" color="blue" fontcolor="blue"]
		label="default"
	}
	"0.0.0.0-255.255.255.255" [label="0.0.0.0-255.255.255.255" color="red2" fontcolor="red2"]
	"0.0.0.0-255.255.255.255" -> "default/frontend[Deployment]" [label="TCP 8080" color="gold2" fontcolor="darkgreen"]
	"default/frontend[Deployment]" -> "0.0.0.0-255.255.255.255" [label="UDP 53" color="gold2" fontcolor="darkgreen"]
	"default/frontend[Deployment]" -> "default/backend[Deployment]" [label="TCP 9090" color="gold2" fontcolor="darkgreen"]
}
```

`svg` graph from `dot` format output can be produced using `graphviz` as following:
```
dot -Tsvg test_outputs/connlist/netpol-analysis-example-minimal_connlist_output.dot -o test_outputs/connlist/netpol-analysis-example-minimal_connlist_output.dot.svg
```
The frames in the graph represent namespaces of the analyzed cluster.

![svg graph](./connlist_example_svg.svg)


### Possible warning
`Route/Ingress specified workload as a backend, but network policies are blocking ingress connections from an arbitrary in-cluster source to this workload. Connectivity map will not include a possibly allowed connection between the ingress controller and this workload.`

Since the analysis assumes the manifest of the ingress controller is unknown, it checks whether an arbitrary workload can access the destination workloads specified in Ingress/Route rules. If such access is not permitted by network policies, this connection is removed from the report. It may be an allowed connection if a network policy specifically allows ingress access to that workload from a specific workload/namespace of the actual ingress controller installed.
