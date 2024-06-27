| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255 | hello-world/workload-a[Deployment] | All Connections |
| hello-world/workload-a[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
## Exposure Analysis Result:
### Egress Exposure:
| src | dst | conn |
|-----|-----|------|
| hello-world/workload-a[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| hello-world/workload-a[Deployment] | entire-cluster | All Connections |
| hello-world/workload-b[Deployment] | [namespace with {foo.com/managed-state=managed}]/[all pods] | TCP 8050 |

### Ingress Exposure:
| dst | src | conn |
|-----|-----|------|
| hello-world/workload-a[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| hello-world/workload-a[Deployment] | entire-cluster | All Connections |
| hello-world/workload-b[Deployment] | [namespace with {foo.com/managed-state=managed}]/[all pods] | TCP 8050 |
