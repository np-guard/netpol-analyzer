package eval

/*
The entities that a Pod can communicate with are identified through a combination of the following
	3 identifiers:

- Other pods that are allowed (exception: a pod cannot block access to itself)
- Namespaces that are allowed
- IP blocks (exception: traffic to and from the node where a Pod is running is always allowed,
	regardless of the IP address of the Pod or the node)
*/

/*
There are two sorts of isolation for a pod: isolation for egress, and isolation for ingress.
By default, if no policies exist in a namespace, then all ingress and egress traffic is allowed
to and from pods in that namespace.

By default, a pod is non-isolated for egress; all outbound connections are allowed. A pod is
isolated for egress if there is any NetworkPolicy that both selects the pod and has "Egress"
in its policyTypes; we say that such a policy applies to the pod for egress. When a pod is
isolated for egress, the only allowed connections from the pod are those allowed by the egress
list of some NetworkPolicy that applies to the pod for egress. The effects of those egress
lists combine additively.

By default, a pod is non-isolated for ingress; all inbound connections are allowed. A pod is
isolated for ingress if there is any NetworkPolicy that both selects the pod and has "Ingress"
in its policyTypes; we say that such a policy applies to the pod for ingress. When a pod is
isolated for ingress, the only allowed connections into the pod are those from the pod's node
and those allowed by the ingress list of some NetworkPolicy that applies to the pod for ingress.
The effects of those ingress lists combine additively.

Network policies do not conflict; they are additive. If any policy or policies apply to a
given pod for a given direction, the connections allowed in that direction from that pod is
the union of what the applicable policies allow. Thus, order of evaluation does not affect
the policy result.

For a connection from a source pod to a destination pod to be allowed, both the egress
policy on the source pod and the ingress policy on the destination pod need to allow the
connection. If either side does not allow the connection, it will not happen.

If no policyTypes are specified on a NetworkPolicy then by default Ingress will always be
set and Egress will be set if the NetworkPolicy has any egress rules. This can be combined
with empty ingress/egress rules to default-deny traffic.

podSelector: This selects particular Pods in the same namespace as the NetworkPolicy which should be allowed as
ingress sources or egress destinations.
namespaceSelector: This selects particular namespaces for which all Pods should be allowed as ingress sources
or egress destinations.
namespaceSelector and podSelector: A single to/from entry that specifies both namespaceSelector and podSelector
selects particular Pods within particular namespaces.

ipBlock: This selects particular IP CIDR ranges to allow as ingress sources or egress destinations.
These should be cluster-external IPs, since Pod IPs are ephemeral and unpredictable.

Cluster ingress and egress mechanisms often require rewriting the source or destination
IP of packets. In cases where this happens, it is not defined whether this happens before
or after NetworkPolicy processing, and the behavior may be different for different combinations
of network plugin, cloud provider, Service implementation, etc.
*/
