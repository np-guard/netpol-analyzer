| src | dst | conn |
|-----|-----|------|
| hello-world/workload-a[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
## Exposure Analysis Result:
### Egress Exposure:
| src | dst | conn |
|-----|-----|------|
| hello-world/workload-a[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| hello-world/workload-a[Deployment] | entire-cluster | All Connections |

### Ingress Exposure:
| dst | src | conn |
|-----|-----|------|
| hello-world/workload-a[Deployment] | [namespace with {effect=NoSchedule}]/[all pods] | TCP 8050 |
| hello-world/workload-a[Deployment] | [namespace with {foo.com/managed-state=managed}]/[all pods] | TCP 8050 |
| hello-world/workload-a[Deployment] | [namespace with {release=stable}]/[all pods] | All Connections |
