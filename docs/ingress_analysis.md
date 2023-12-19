# Ingress Analysis

## Supported Ingress Controllers:

Ingress Controllers considered for ingress analysis:
- Openshift ingress controller 
- Nginx ingress controller

#### Namespace Labels Supported:

|Ingress Controller | Namespace labels supported|
|-------------------|---------------------------|
|Openshift ingress controller |namespace.name: openshift-ingress-operator|
||kubernetes.io/metadata.name: openshift-ingress-operator|
||network.openshift.io/policy-group: ingress|
|Nginx ingress controller |tier: ingress|
||kubernetes.io/metadata.name: ingress-nginx|
||app.kubernetes.io/part-of: ingress-nginx|

## Allowed Ingress Connections And Output:

- Capturing ingress-controller by `podSelector` also is not supported yet. 
if ingress connections from a specific ingress-controller namespace (from above) is allowed to a cluster's peer, we assume it is allowed from any ingress-controller-pod in that namespace.

- For each supported ingress-controller, the connectivity line is of the form:
`{<ingress-controller-namespace-name>}` => `dst` : `connections`, where `dst` is a workload in the cluster.

- When ingress connection is enabled to a workload by Ingress/Route objects and there is no network-policy rule that denies or restricts this connection, the output will include a connectivity line for each specific ingress-controller from the list above

- When ingress connection is enabled by Ingress/Route, and restricted for one ingress-controller by the a network-policy rule, only the connectivity line from the specified ingress-controller namespace will be reported.

- If ingress connection is enabled by Ingress/Route but denied by network-policy rules, then ingress connection will be blocked and will not appear in the connectivity report.

- If ingress connection is enabled by Ingress/Route but restricted by network-policy rules to another ingress-controller (that is not supported) then ingress connection will be blocked and will not appear in the connectivity report either.

- This analysis is currently activated only with `--dirpath` flag, and not on a live cluster.
It assumes that the ingress controller Pod is unknown, and thus using this notation of its namespace.


### Possible warning
`Route/Ingress specified workload as a backend, but network policies are blocking ingress connections from an arbitrary in-cluster source to this workload. Connectivity map will not include a possibly allowed connection between the ingress controller and this workload.`

Since the analysis considers only the mentioned above specific ingress controllers, it checks whether an arbitrary workload in one of the specified namespaces can access the destination workloads specified in Ingress/Route rules. If such access is not permitted by network policies, this connection is removed from the report. It may be an allowed connection if a network policy specifically allows ingress access to that workload from a specific workload/namespace of the actual different ingress controller installed.