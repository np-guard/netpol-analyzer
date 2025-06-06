| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255[External] | hello-world/matching-workload2[Deployment] | All Connections |
| 0.0.0.0-255.255.255.255[External] | hello-world/workload-b[Deployment] | All Connections |
| 0.0.0.0-255.255.255.255[External] | matching-ns/matching-workload1[Deployment] | All Connections |
| hello-world/matching-workload2[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| hello-world/matching-workload2[Deployment] | hello-world/workload-a[Deployment] | All Connections |
| hello-world/matching-workload2[Deployment] | hello-world/workload-b[Deployment] | All Connections |
| hello-world/matching-workload2[Deployment] | matching-ns/matching-workload1[Deployment] | All Connections |
| hello-world/workload-a[Deployment] | hello-world/matching-workload2[Deployment] | All Connections |
| hello-world/workload-b[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| hello-world/workload-b[Deployment] | hello-world/matching-workload2[Deployment] | All Connections |
| hello-world/workload-b[Deployment] | hello-world/workload-a[Deployment] | All Connections |
| hello-world/workload-b[Deployment] | matching-ns/matching-workload1[Deployment] | All Connections |
| matching-ns/matching-workload1[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| matching-ns/matching-workload1[Deployment] | hello-world/matching-workload2[Deployment] | All Connections |
| matching-ns/matching-workload1[Deployment] | hello-world/workload-a[Deployment] | All Connections |
| matching-ns/matching-workload1[Deployment] | hello-world/workload-b[Deployment] | All Connections |
## Exposure Analysis Result:
### Egress Exposure:
| src | dst | conn |
|-----|-----|------|
| hello-world/matching-workload2[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| hello-world/matching-workload2[Deployment] | entire-cluster | All Connections |
| hello-world/workload-a[Deployment] | hello-world/[pod with {{Key:app,Operator:DoesNotExist,Values:[],}}] | All Connections |
| hello-world/workload-b[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| hello-world/workload-b[Deployment] | entire-cluster | All Connections |
| matching-ns/matching-workload1[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| matching-ns/matching-workload1[Deployment] | entire-cluster | All Connections |

### Ingress Exposure:
| dst | src | conn |
|-----|-----|------|
| hello-world/matching-workload2[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| hello-world/matching-workload2[Deployment] | entire-cluster | All Connections |
| hello-world/workload-a[Deployment] | [namespace with {{Key:env,Operator:DoesNotExist,Values:[],}}]/[all pods] | All Connections |
| hello-world/workload-b[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| hello-world/workload-b[Deployment] | entire-cluster | All Connections |
| matching-ns/matching-workload1[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| matching-ns/matching-workload1[Deployment] | entire-cluster | All Connections |
