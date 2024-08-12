| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255 | hello-world/workload-b[Deployment] | All Connections |
| 0.0.0.0-255.255.255.255 | matching-ns/matching-workload[Deployment] | All Connections |
| hello-world/workload-a[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| hello-world/workload-a[Deployment] | hello-world/workload-b[Deployment] | All Connections |
| hello-world/workload-a[Deployment] | matching-ns/matching-workload[Deployment] | All Connections |
| hello-world/workload-b[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| hello-world/workload-b[Deployment] | hello-world/workload-a[Deployment] | All Connections |
| hello-world/workload-b[Deployment] | matching-ns/matching-workload[Deployment] | All Connections |
| matching-ns/matching-workload[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| matching-ns/matching-workload[Deployment] | hello-world/workload-a[Deployment] | TCP 8050,8090 |
| matching-ns/matching-workload[Deployment] | hello-world/workload-b[Deployment] | All Connections |
## Exposure Analysis Result:
### Egress Exposure:
| src | dst | conn |
|-----|-----|------|
| hello-world/workload-a[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| hello-world/workload-a[Deployment] | entire-cluster | All Connections |
| hello-world/workload-b[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| hello-world/workload-b[Deployment] | entire-cluster | All Connections |
| matching-ns/matching-workload[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| matching-ns/matching-workload[Deployment] | entire-cluster | All Connections |

### Ingress Exposure:
| dst | src | conn |
|-----|-----|------|
| hello-world/workload-a[Deployment] | [namespace with {{Key:foo.com/managed-state,Operator:In,Values:[managed],}}]/[all pods] | TCP 8050,8090 |
| hello-world/workload-a[Deployment] | entire-cluster | TCP 8050 |
| hello-world/workload-b[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| hello-world/workload-b[Deployment] | entire-cluster | All Connections |
| matching-ns/matching-workload[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| matching-ns/matching-workload[Deployment] | entire-cluster | All Connections |
