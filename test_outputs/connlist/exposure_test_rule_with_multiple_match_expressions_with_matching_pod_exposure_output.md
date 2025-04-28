| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255 | hello-world/matching-workload[Deployment] | All Connections |
| 0.0.0.0-255.255.255.255 | hello-world/workload-b[Deployment] | All Connections |
| hello-world/matching-workload[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| hello-world/matching-workload[Deployment] | hello-world/workload-a[Deployment] | All Connections |
| hello-world/matching-workload[Deployment] | hello-world/workload-b[Deployment] | All Connections |
| hello-world/workload-a[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| hello-world/workload-a[Deployment] | hello-world/matching-workload[Deployment] | All Connections |
| hello-world/workload-a[Deployment] | hello-world/workload-b[Deployment] | All Connections |
| hello-world/workload-b[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| hello-world/workload-b[Deployment] | hello-world/matching-workload[Deployment] | All Connections |
## Exposure Analysis Result:
### Egress Exposure:
| src | dst | conn |
|-----|-----|------|
| hello-world/matching-workload[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| hello-world/matching-workload[Deployment] | entire-cluster | All Connections |
| hello-world/workload-a[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| hello-world/workload-a[Deployment] | entire-cluster | All Connections |
| hello-world/workload-b[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| hello-world/workload-b[Deployment] | entire-cluster | All Connections |

### Ingress Exposure:
| dst | src | conn |
|-----|-----|------|
| hello-world/matching-workload[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| hello-world/matching-workload[Deployment] | entire-cluster | All Connections |
| hello-world/workload-a[Deployment] | hello-world/[pod with {{Key:app,Operator:NotIn,Values:[b-app c-app d-app],},{Key:env,Operator:DoesNotExist,Values:[],},{Key:role,Operator:In,Values:[frontend web api],},{Key:tier,Operator:Exists,Values:[],}}] | All Connections |
| hello-world/workload-b[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| hello-world/workload-b[Deployment] | entire-cluster | All Connections |
