| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255[External] | hello-world/workload-b[Deployment] | All Connections |
| hello-world/workload-a[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| hello-world/workload-a[Deployment] | hello-world/workload-b[Deployment] | All Connections |
| hello-world/workload-b[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| hello-world/workload-b[Deployment] | hello-world/workload-a[Deployment] | TCP 9090 |
## Exposure Analysis Result:
### Egress Exposure:
| src | dst | conn |
|-----|-----|------|
| hello-world/workload-a[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| hello-world/workload-a[Deployment] | entire-cluster | All Connections |
| hello-world/workload-b[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| hello-world/workload-b[Deployment] | entire-cluster | All Connections |

### Ingress Exposure:
| dst | src | conn |
|-----|-----|------|
| hello-world/workload-a[Deployment] | hello-world/[pod with {{Key:app,Operator:DoesNotExist,Values:[],}}] | TCP 8080 |
| hello-world/workload-a[Deployment] | hello-world/[pod with {{Key:app,Operator:NotIn,Values:[x],}}] | TCP 9090 |
| hello-world/workload-b[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| hello-world/workload-b[Deployment] | entire-cluster | All Connections |
