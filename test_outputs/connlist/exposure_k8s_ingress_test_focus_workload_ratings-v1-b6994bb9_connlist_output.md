| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255 | default/ratings-v1-b6994bb9[ReplicaSet] | All Connections |
| default/details-v1-79f774bdb9[ReplicaSet] | default/ratings-v1-b6994bb9[ReplicaSet] | All Connections |
| default/productpage-v1-6b746f74dc[ReplicaSet] | default/ratings-v1-b6994bb9[ReplicaSet] | All Connections |
| default/ratings-v1-b6994bb9[ReplicaSet] | 0.0.0.0-255.255.255.255 | All Connections |
| default/ratings-v1-b6994bb9[ReplicaSet] | default/details-v1-79f774bdb9[ReplicaSet] | All Connections |
| default/ratings-v1-b6994bb9[ReplicaSet] | default/productpage-v1-6b746f74dc[ReplicaSet] | All Connections |
| default/ratings-v1-b6994bb9[ReplicaSet] | default/reviews-v1-545db77b95[ReplicaSet] | All Connections |
| default/ratings-v1-b6994bb9[ReplicaSet] | default/reviews-v2-7bf8c9648f[ReplicaSet] | All Connections |
| default/ratings-v1-b6994bb9[ReplicaSet] | default/reviews-v3-84779c7bbc[ReplicaSet] | All Connections |
| default/reviews-v1-545db77b95[ReplicaSet] | default/ratings-v1-b6994bb9[ReplicaSet] | All Connections |
| default/reviews-v2-7bf8c9648f[ReplicaSet] | default/ratings-v1-b6994bb9[ReplicaSet] | All Connections |
| default/reviews-v3-84779c7bbc[ReplicaSet] | default/ratings-v1-b6994bb9[ReplicaSet] | All Connections |
## Exposure Analysis Result:
| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255 | default/ratings-v1-b6994bb9[ReplicaSet] | All Connections |
| default/ratings-v1-b6994bb9[ReplicaSet] | 0.0.0.0-255.255.255.255 | All Connections |
| default/ratings-v1-b6994bb9[ReplicaSet] | entire-cluster | All Connections |
| entire-cluster | default/ratings-v1-b6994bb9[ReplicaSet] | All Connections |