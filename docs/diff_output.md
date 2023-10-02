# Diff command - connectivity diff output :

Diff command requires two folders, dir1 and dir2, each containing Kubernetes manifests, including network policies. 
The diff output provides a summary of changed/added/removed connections from dir2 with respect to allowed connections from dir1.

## Examples Output 

```
$ ./bin/k8snetpolicy diff --dir1 tests/netpol-analysis-example-minimal/ --dir2 tests/netpol-diff-example-minimal/ -o txt

Connectivity diff:
diff-type: changed, source: default/frontend[Deployment], destination: default/backend[Deployment], dir1:  TCP 9090, dir2: TCP 9090,UDP 53
diff-type: added, source: 0.0.0.0-255.255.255.255, destination: default/backend[Deployment], dir1:  No Connections, dir2: TCP 9090
```

```
$ ./bin/k8snetpolicy diff --dir1 tests/netpol-analysis-example-minimal/ --dir2 tests/netpol-diff-example-minimal/ -o md

| diff-type | source | destination | dir1 | dir2 | workloads-diff-info |
|-----------|--------|-------------|------|------|---------------------|
| changed | default/frontend[Deployment] | default/backend[Deployment] | TCP 9090 | TCP 9090,UDP 53 |  |
| added | 0.0.0.0-255.255.255.255 | default/backend[Deployment] | No Connections | TCP 9090 |  |
```

```
$ ./bin/k8snetpolicy diff --dir1 tests/netpol-analysis-example-minimal/ --dir2 tests/netpol-diff-example-minimal/ -o csv

diff-type,source,destination,dir1,dir2,workloads-diff-info
changed,default/frontend[Deployment],default/backend[Deployment],TCP 9090,"TCP 9090,UDP 53",
added,0.0.0.0-255.255.255.255,default/backend[Deployment],No Connections,TCP 9090,
```

```
$ ./bin/k8snetpolicy diff --dir1 tests/netpol-analysis-example-minimal/ --dir2 tests/netpol-diff-example-minimal/ -o dot

digraph {
        "0.0.0.0-255.255.255.255" [label="0.0.0.0-255.255.255.255" color="blue" fontcolor="blue"]
        "default/backend[Deployment]" [label="default/backend[Deployment]" color="blue" fontcolor="blue"]
        "default/frontend[Deployment]" [label="default/frontend[Deployment]" color="blue" fontcolor="blue"]
        "0.0.0.0-255.255.255.255" -> "default/backend[Deployment]" [label="TCP 9090" color="#008000" fontcolor="#008000"]
        "0.0.0.0-255.255.255.255" -> "default/frontend[Deployment]" [label="TCP 8080" color="grey" fontcolor="grey"]
        "default/frontend[Deployment]" -> "0.0.0.0-255.255.255.255" [label="UDP 53" color="grey" fontcolor="grey"]
        "default/frontend[Deployment]" -> "default/backend[Deployment]" [label="TCP 9090,UDP 53 (old: TCP 9090)" color="magenta" fontcolor="magenta"]
        nodesep=0.5
        subgraph cluster_legend {
                label="Legend"
                fontsize = 10
                margin=0
                a [style=invis height=0 width=0]
                b [style=invis height=0 width=0]
                c [style=invis height=0 width=0]
                d [style=invis height=0 width=0]
                e [style=invis height=0 width=0]
                f [style=invis height=0 width=0]
                g [style=invis height=0 width=0]
                h [style=invis height=0 width=0]
                {rank=source a b c d}
                {rank=same e f g h}
                a -> b [label="added connection", color="#008000" fontcolor="#008000" fontsize = 10 arrowsize=0.2]
                c -> d [label="removed connection", color="red" fontcolor="red" fontsize = 10 arrowsize=0.2]
                e -> f [label="changed connection", color="magenta" fontcolor="magenta" fontsize = 10 arrowsize=0.2]
                g -> h [label="non-changed connection", color="grey" fontcolor="grey" fontsize = 10 arrowsize=0.2]
                np [label="new peer" color="#008000" fontcolor="#008000" fontsize = 10]
                lp [label="lost peer" color="red" fontcolor="red" fontsize = 10]
                pp [label="persistent peer" color="blue" fontcolor="blue" fontsize = 10]
                {rank=sink np lp pp}
                np->lp [style=invis]
                lp->pp [style=invis]
        }
}
```

### Understanding the output
Each line in the output represents an allowed connection that has been added/removed/changed on dir2 with respect to dir1. The `workloads-diff-info` adds information about added/removed workload related to the added/removed connection, if relevant.

#### Dot Output:
Diff Dot Output Creates A Graph as following:
- `Green` edges for `added connections`
- `Red` edges for `removed connections`
- `Magenta` edges for `changed connections`
- `Grey` edges for `unchanged connections`
- `Blue` nodes for `persistent peers`
- `Green` nodes for 'new peers`
- `Red` nodes for `lost peers`