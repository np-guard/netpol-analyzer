| src | dst | conn |
|-----|-----|------|
## Exposure Analysis Result:
### Egress Exposure:
| src | dst | conn |
|-----|-----|------|
| hello-world/workload-a[Deployment] | [namespace with {foo.com/managed-state=managed}]/[all pods] | TCP 8050 |

### Ingress Exposure:
| dst | src | conn |
|-----|-----|------|
| hello-world/workload-a[Deployment] | [namespace with {foo.com/managed-state=managed}]/[all pods] | TCP 8000,8090 |
| hello-world/workload-a[Deployment] | entire-cluster | TCP 8000 |
