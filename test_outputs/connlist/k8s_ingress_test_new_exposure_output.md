| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255[External] | default/unicorn[Deployment] | All Connections |
| default/reviews-v1-545db77b95[ReplicaSet] | default/productpage-v1-6b746f74dc[ReplicaSet] | TCP 9080 |
| default/reviews-v1-545db77b95[ReplicaSet] | default/ratings-v1-b6994bb9[ReplicaSet] | TCP 9080 |
| default/reviews-v2-7bf8c9648f[ReplicaSet] | default/productpage-v1-6b746f74dc[ReplicaSet] | TCP 9080 |
| default/reviews-v2-7bf8c9648f[ReplicaSet] | default/ratings-v1-b6994bb9[ReplicaSet] | TCP 9080 |
| default/reviews-v3-84779c7bbc[ReplicaSet] | default/productpage-v1-6b746f74dc[ReplicaSet] | TCP 9080 |
| default/reviews-v3-84779c7bbc[ReplicaSet] | default/ratings-v1-b6994bb9[ReplicaSet] | TCP 9080 |
| default/unicorn[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| default/unicorn[Deployment] | default/details-v1-79f774bdb9[ReplicaSet] | TCP 9080 |
| {ingress-controller} | default/details-v1-79f774bdb9[ReplicaSet] | TCP 9080 |
| {ingress-controller} | default/unicorn[Deployment] | TCP 8080 |
## Exposure Analysis Result:
### Egress Exposure:
| src | dst | conn |
|-----|-----|------|
| default/unicorn[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| default/unicorn[Deployment] | entire-cluster | All Connections |

### Ingress Exposure:
| dst | src | conn |
|-----|-----|------|
| default/details-v1-79f774bdb9[ReplicaSet] | entire-cluster | TCP 9080 |
| default/unicorn[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| default/unicorn[Deployment] | entire-cluster | All Connections |
