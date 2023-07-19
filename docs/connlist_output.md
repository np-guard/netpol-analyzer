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
