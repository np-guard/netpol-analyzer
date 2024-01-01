# Ingress Analysis

Ingress Analysis is performed when input resources include Ingress/Route objects.

For workloads that are selected by Ingress/Route objects, we analyze if ingress access from ingress-controllers is allowed to them.

## Supported Ingress Controllers:

Ingress Controllers considered for ingress analysis:
- Openshift ingress controller ([view official docs](https://docs.openshift.com/container-platform/4.14/networking/ingress-operator.html#nw-ingress-view_configuring-ingress))
- Nginx ingress controller ([view official docs](https://docs.nginx.com/nginx-ingress-controller/overview))

#### Namespace Labels Checked :

Ingress access to a workload selected by Ingress/Route object may be restricted by network-policies rules.
In order to check if a network-policy rule enables access to such workload we need to check if a rule's namespaceSelector matches any of supported ingress controllers' namespaces.
if at least one label of the following is used in the namespaceSelector, so ingress access from the relevant Ingress-Controller is enabled.

|Ingress Controller | Namespace labels supported| More Details |
|-------------------|---------------------------|--------------|
|Openshift ingress controller |namespace.name: openshift-ingress-operator|[openshift-ingress-operator namespace link](https://github.com/openshift/cluster-ingress-operator/blob/f9dd81ab522f72233e2608f5e57a43e79a5079b5/manifests/00-namespace.yaml#L10)|
||kubernetes.io/metadata.name: openshift-ingress-operator||
||openshift.io/cluster-monitoring: "true"||
|Nginx ingress controller |kubernetes.io/metadata.name: ingress-nginx|[nginx-ingress namespace link](https://github.com/nginxinc/kubernetes-ingress/blob/main/deployments/common/ns-and-sa.yaml)|


## Allowed Ingress Connections And Output:

- Selecting ingress-controller deployment by `podSelector` in a network-policy rule is not supported yet. 
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
`Route/Ingress specified workload as a backend, but network policies are blocking external ingress access by nginx or openshift ingress controllers. Connectivity map will not include a possibly allowed connection between the ingress controller and this workload.`

Since the analysis considers only the mentioned above specific ingress controllers, it checks whether an arbitrary workload in one of the specified namespaces can access the destination workloads specified in Ingress/Route rules. If such access is not permitted by network policies, this connection is removed from the report. It may be an allowed connection if a network policy specifically allows ingress access to that workload from a specific workload/namespace of an actual different ingress controller installed.