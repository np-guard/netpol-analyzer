| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255 | hello-world/workload-b[Deployment] | All Connections |
| hello-world/workload-b[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| hello-world/workload-b[Deployment] | hello-world/workload-a[Deployment] | All Connections |
## Exposure Analysis Result:
### Egress Exposure:
| src | dst | conn |
|-----|-----|------|
| hello-world/workload-a[Deployment] | hello-world/[pod with {{Key:app,Operator:NotIn,Values:[a-app b-app],}}] | All Connections |
| hello-world/workload-b[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| hello-world/workload-b[Deployment] | entire-cluster | All Connections |

### Ingress Exposure:
| dst | src | conn |
|-----|-----|------|
| hello-world/workload-a[Deployment] | [namespace with {{Key:env,Operator:NotIn,Values:[env-a env-b],}}]/[all pods] | All Connections |
| hello-world/workload-b[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| hello-world/workload-b[Deployment] | entire-cluster | All Connections |