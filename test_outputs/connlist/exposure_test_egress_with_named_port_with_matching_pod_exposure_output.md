| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255[External] | matching-ns/matching-workload[Deployment] | All Connections |
| hello-world/workload-a[Deployment] | matching-ns/matching-workload[Deployment] | TCP 8090 |
| matching-ns/matching-workload[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| matching-ns/matching-workload[Deployment] | hello-world/workload-a[Deployment] | TCP 8000 |
## Exposure Analysis Result:
### Egress Exposure:
| src | dst | conn |
|-----|-----|------|
| hello-world/workload-a[Deployment] | [namespace with {{Key:foo.com/managed-state,Operator:In,Values:[managed],}}]/[all pods] | TCP http |
| matching-ns/matching-workload[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| matching-ns/matching-workload[Deployment] | entire-cluster | All Connections |

### Ingress Exposure:
| dst | src | conn |
|-----|-----|------|
| hello-world/workload-a[Deployment] | entire-cluster | TCP 8000 |
| matching-ns/matching-workload[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| matching-ns/matching-workload[Deployment] | entire-cluster | All Connections |
