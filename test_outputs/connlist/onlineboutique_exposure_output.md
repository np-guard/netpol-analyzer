| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255[External] | default/redis-cart-78746d49dc[ReplicaSet] | All Connections |
| default/checkoutservice-69c8ff664b[ReplicaSet] | default/cartservice-74f56fd4b[ReplicaSet] | TCP 7070 |
| default/checkoutservice-69c8ff664b[ReplicaSet] | default/currencyservice-77654bbbdd[ReplicaSet] | TCP 7000 |
| default/checkoutservice-69c8ff664b[ReplicaSet] | default/emailservice-54c7c5d9d[ReplicaSet] | TCP 8080 |
| default/checkoutservice-69c8ff664b[ReplicaSet] | default/paymentservice-bbcbdc6b6[ReplicaSet] | TCP 50051 |
| default/checkoutservice-69c8ff664b[ReplicaSet] | default/productcatalogservice-68765d49b6[ReplicaSet] | TCP 3550 |
| default/checkoutservice-69c8ff664b[ReplicaSet] | default/shippingservice-5bd985c46d[ReplicaSet] | TCP 50051 |
| default/frontend-99684f7f8[ReplicaSet] | default/adservice-77d5cd745d[ReplicaSet] | TCP 9555 |
| default/frontend-99684f7f8[ReplicaSet] | default/cartservice-74f56fd4b[ReplicaSet] | TCP 7070 |
| default/frontend-99684f7f8[ReplicaSet] | default/checkoutservice-69c8ff664b[ReplicaSet] | TCP 5050 |
| default/frontend-99684f7f8[ReplicaSet] | default/currencyservice-77654bbbdd[ReplicaSet] | TCP 7000 |
| default/frontend-99684f7f8[ReplicaSet] | default/productcatalogservice-68765d49b6[ReplicaSet] | TCP 3550 |
| default/frontend-99684f7f8[ReplicaSet] | default/recommendationservice-5f8c456796[ReplicaSet] | TCP 8080 |
| default/frontend-99684f7f8[ReplicaSet] | default/shippingservice-5bd985c46d[ReplicaSet] | TCP 50051 |
| default/loadgenerator-555fbdc87d[ReplicaSet] | default/frontend-99684f7f8[ReplicaSet] | TCP 8080 |
| default/recommendationservice-5f8c456796[ReplicaSet] | default/productcatalogservice-68765d49b6[ReplicaSet] | TCP 3550 |
| default/redis-cart-78746d49dc[ReplicaSet] | 0.0.0.0-255.255.255.255[External] | All Connections |
## Exposure Analysis Result:
### Egress Exposure:
| src | dst | conn |
|-----|-----|------|
| default/checkoutservice-69c8ff664b[ReplicaSet] | [all namespaces]/[pod with {k8s-app=kube-dns}] | UDP 53 |
| default/frontend-99684f7f8[ReplicaSet] | [all namespaces]/[pod with {k8s-app=kube-dns}] | UDP 53 |
| default/loadgenerator-555fbdc87d[ReplicaSet] | [all namespaces]/[pod with {k8s-app=kube-dns}] | UDP 53 |
| default/recommendationservice-5f8c456796[ReplicaSet] | [all namespaces]/[pod with {k8s-app=kube-dns}] | UDP 53 |
| default/redis-cart-78746d49dc[ReplicaSet] | 0.0.0.0-255.255.255.255[External] | All Connections |
| default/redis-cart-78746d49dc[ReplicaSet] | entire-cluster | All Connections |

### Ingress Exposure:
| dst | src | conn |
|-----|-----|------|
| default/redis-cart-78746d49dc[ReplicaSet] | 0.0.0.0-255.255.255.255[External] | All Connections |
| default/redis-cart-78746d49dc[ReplicaSet] | entire-cluster | All Connections |
