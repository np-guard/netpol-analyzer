| src | dst | conn |
|-----|-----|------|
## Exposure Analysis Result:
### Egress Exposure:
| src | dst | conn |
|-----|-----|------|
| hello-world/workload-a[Deployment] | [namespace with {{Key:foo.com/managed-state,Operator:In,Values:[managed],}}]/[all pods] | TCP http |

### Ingress Exposure:
| dst | src | conn |
|-----|-----|------|
| hello-world/workload-a[Deployment] | entire-cluster | TCP 8000 |
