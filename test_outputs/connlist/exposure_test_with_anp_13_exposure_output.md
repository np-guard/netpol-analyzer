| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255[External] | hello-world/workload-a[Deployment] | All Connections |
| 0.0.0.0-255.255.255.255[External] | hello-world/workload-b[Deployment] | All Connections |
| hello-world/workload-b[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| hello-world/workload-b[Deployment] | hello-world/workload-a[Deployment] | TCP 9090 |
## Exposure Analysis Result:
### Egress Exposure:
| src | dst | conn |
|-----|-----|------|
| hello-world/workload-a[Deployment] | new-ns/[pod with {app=new-app}] | TCP 80 |
| hello-world/workload-b[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| hello-world/workload-b[Deployment] | entire-cluster | All Connections |

### Ingress Exposure:
| dst | src | conn |
|-----|-----|------|
| hello-world/workload-a[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| hello-world/workload-a[Deployment] | hello-world/[all pods] | TCP 9090 |
| hello-world/workload-b[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| hello-world/workload-b[Deployment] | entire-cluster | All Connections |
