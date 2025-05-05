# Diff command - connectivity diff output :

Diff command requires two folders, dir1 and dir2, each containing Kubernetes manifests, including network policies. 
The diff output provides a summary of changed/added/removed connections from dir2 with respect to allowed connections from dir1.

## Examples Output 

Diff output in `txt` format:
```
$ ./bin/k8snetpolicy diff --dir1 tests/netpol-analysis-example-minimal/ --dir2 tests/netpol-diff-example-minimal/ -o txt

Connectivity diff:
diff-type: changed, source: default/frontend[Deployment], destination: default/backend[Deployment], dir1:  TCP 9090, dir2: TCP 9090,UDP 53
diff-type: added, source: 0.0.0.0-255.255.255.255, destination: default/backend[Deployment], dir1:  No Connections, dir2: TCP 9090
```

Diff output in `md` format:
```
$ ./bin/k8snetpolicy diff --dir1 tests/netpol-analysis-example-minimal/ --dir2 tests/netpol-diff-example-minimal/ -o md
```

| diff-type | source | destination | dir1 | dir2 | workloads-diff-info |
|-----------|--------|-------------|------|------|---------------------|
| changed | default/frontend[Deployment] | default/backend[Deployment] | TCP 9090 | TCP 9090,UDP 53 |  |
| added | 0.0.0.0-255.255.255.255 | default/backend[Deployment] | No Connections | TCP 9090 |  |

Diff output in `csv` format:
```
$ ./bin/k8snetpolicy diff --dir1 tests/netpol-analysis-example-minimal/ --dir2 tests/netpol-diff-example-minimal/ -o csv

diff-type,source,destination,dir1,dir2,workloads-diff-info
changed,default/frontend[Deployment],default/backend[Deployment],TCP 9090,"TCP 9090,UDP 53",
added,0.0.0.0-255.255.255.255,default/backend[Deployment],No Connections,TCP 9090,
```

Diff output in `dot` format:

In dot output graphs, all the peers of the analyzed cluster are grouped by their namespaces.

```
$ ./bin/k8snetpolicy diff --dir1 tests/netpol-analysis-example-minimal/ --dir2 tests/netpol-diff-example-minimal/ -o dot

digraph {
        subgraph cluster_default {
                "default/backend[Deployment]" [label="backend[Deployment]" color="blue" fontcolor="blue"]    
                "default/frontend[Deployment]" [label="frontend[Deployment]" color="blue" fontcolor="blue"]  
                label="default"
        }
        "0.0.0.0-255.255.255.255" [label="0.0.0.0-255.255.255.255" color="blue" fontcolor="blue"]
        "0.0.0.0-255.255.255.255" -> "default/backend[Deployment]" [label="TCP 9090" color="#008000" fontcolor="#008000"]
        "0.0.0.0-255.255.255.255" -> "default/frontend[Deployment]" [label="TCP 8080" color="grey" fontcolor="grey"]
        "default/frontend[Deployment]" -> "0.0.0.0-255.255.255.255" [label="UDP 53" color="grey" fontcolor="grey"]
        "default/frontend[Deployment]" -> "default/backend[Deployment]" [label="TCP 9090,UDP 53 (dir1: TCP 9090)" color="magenta" fontcolor="magenta"]
}
```

`svg` graph from `dot` format output can be produced using `graphviz` as following:

```
$ dot -Tsvg test_outputs/diff/diff_between_netpol-diff-example-minimal_and_netpol-analysis-example-minimal.dot -O
```
or by running the command with `svg` format as following:
```
$ ./bin/k8snetpolicy diff --dir1 tests/netpol-analysis-example-minimal/ --dir2 tests/netpol-diff-example-minimal/ -o svg -f ./diff_example_svg.svg
```

The frames in the graph represent namespaces of the analyzed cluster.


![svg graph](./diff_example_svg.svg)

### Understanding the output
Each line in the output represents an allowed connection that has been added/removed/changed on dir2 with respect to dir1. The `workloads-diff-info` adds information about added/removed workload related to the added/removed connection, if relevant.

#### DOT Graph Legend:

![svg legend](./legend.svg)