# Exposure Analysis

While connectivity report focuses on allowed connections between two workloads in the manifests or between workloads and external-ip blocks/ ingress-controller; 
Exposure-analysis report provides whether a peer in the manifests is exposed to workloads which are not included in the input manifests.

## Exposure Cases: 
Exposure data of a workload contains potential ingress and egress connections which the peer is exposed to.

Conditions for generating exposure items:
### Simple Cases: 
1. cases of generating exposure items where an exposed workload is not captured by any policy:
    - A peer that is not selected by any network-policy is exposed to all end-points (entire-cluster and external ip-blocks).
    - A peer which is selected by policies which affects only one direction, is exposed on the other direction to all end-points.

2. cases where an exposed workload is captured by some policies, and of generating exposure items from policy rules when
there are no other policies with rules contradicting/controverting those ones:
    - A peer which is selected by policies affecting any direction but with empty rules list is exposed to all end-points either.
    - A network-policy rule which contains empty namespaceSelector exposes the peer to entire-cluster on the affected direction.
    - A network-policy rule which contains empty namespaceSelector and empty podSelector exposes the peer to entire-cluster on the affected direction.
    - A network-policy rule which contains selectors without any match in the manifests exposes the peer to any pod matching the rule's selectors on the affected direction
    - A network-policy rule with empty namespaceSelector, but non-empty podSelector exposes the peer to any pod matching the podSelector in any namespace in the cluster.
    - A netwok-policy rule without namespaceSelector, but non-empty podSelector exposes the peer to any pod matching the podSelector in the namespace of the policy.
    - A network-policy rule without or with empty podSelector, but non-empty namespaceSelector exposes the peer to all pods in any namespace matching the namespaceSelector.

## Running Exposure Analysis 

by running list command with `--exposure` flag

`./bin/k8snetpolicy list --dirpath <testing-dir> --exposure`

## Usage

Running exposure-analysis gives feedback on network-policy input resources and helps validating them as following:
- reveals pods which are allowed to communicate with any end-point in the world; which is a potential security-risk
- reveals imprecise pod selectors, namespace selectors and ip-Block ranges; which are possible to unwillingly expose the peer to new pods in the future.
- gives a clear visibility of connectivity based on all network-policies; to confirm that they're working as intended

## Example Output:

an example with exposure analysis output in `txt` format:

```
$ ./bin/k8snetpolicy list --dirpath tests/test_exposure_minimal_netpol_analysis/ --exposure

0.0.0.0-255.255.255.255 => default/frontend[Deployment] : TCP 8080
default/frontend[Deployment] => 0.0.0.0-255.255.255.255 : UDP 53
default/frontend[Deployment] => default/backend[Deployment] : TCP 9090

Exposure Analysis Result:
Egress Exposure:
default/frontend[Deployment]    =>      0.0.0.0-255.255.255.255 : UDP 53
default/frontend[Deployment]    =>      entire-cluster : UDP 53

Ingress Exposure:
default/backend[Deployment]     <=      entire-cluster : TCP 9090
default/frontend[Deployment]    <=      0.0.0.0-255.255.255.255 : TCP 8080
default/frontend[Deployment]    <=      entire-cluster : TCP 8080
```

an example with exposure analysis output in `dot` format:

```
$ ./bin/k8snetpolicy list --dirpath tests/test_exposure_minimal_netpol_analysis/ --exposure -o dot

digraph {
    subgraph "cluster_default" {
            color="black"
            fontcolor="black"
            "default/backend[Deployment]" [label="backend[Deployment]" color="blue" fontcolor="blue"]
            "default/frontend[Deployment]" [label="frontend[Deployment]" color="blue" fontcolor="blue"]
            label="default"
    }
    "0.0.0.0-255.255.255.255" [label="0.0.0.0-255.255.255.255" color="red2" fontcolor="red2"]
    "entire-cluster" [label="entire-cluster" color="red2" fontcolor="red2" shape=diamond]
    "0.0.0.0-255.255.255.255" -> "default/frontend[Deployment]" [label="TCP 8080" color="gold2" fontcolor="darkgreen"]
    "default/frontend[Deployment]" -> "0.0.0.0-255.255.255.255" [label="UDP 53" color="gold2" fontcolor="darkgreen"]
    "default/frontend[Deployment]" -> "default/backend[Deployment]" [label="TCP 9090" color="gold2" fontcolor="darkgreen"]
    "default/frontend[Deployment]" -> "entire-cluster" [label="UDP 53" color="gold2" fontcolor="darkgreen" weight=0.5]
    "entire-cluster" -> "default/backend[Deployment]" [label="TCP 9090" color="gold2" fontcolor="darkgreen" weight=1]
    "entire-cluster" -> "default/frontend[Deployment]" [label="TCP 8080" color="gold2" fontcolor="darkgreen" weight=1]
}

```
`svg` graph matching `dot` format output: [here](./exposure_analysis_example.svg)
