| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255 | hello-world/workload-b[Deployment] | All Connections |
| hello-world/workload-a[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| hello-world/workload-a[Deployment] | hello-world/workload-b[Deployment] | All Connections |
| hello-world/workload-b[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| hello-world/workload-b[Deployment] | hello-world/workload-a[Deployment] | TCP 8080,9090 |
## Exposure Analysis Result:
### Egress Exposure:
| src | dst | conn |
|-----|-----|------|
| hello-world/workload-a[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| hello-world/workload-a[Deployment] | entire-cluster | All Connections |
| hello-world/workload-b[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| hello-world/workload-b[Deployment] | entire-cluster | All Connections |

### Ingress Exposure:
| dst | src | conn |
|-----|-----|------|
| hello-world/workload-a[Deployment] | hello-world/[pod with {{Key:role,Operator:NotIn,Values:[w x y z],}}] | TCP 8080 |
| hello-world/workload-a[Deployment] | hello-world/[pod with {{Key:role,Operator:NotIn,Values:[x y],}}] | TCP 9090 |
| hello-world/workload-b[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| hello-world/workload-b[Deployment] | entire-cluster | All Connections |
