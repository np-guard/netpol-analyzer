| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255 | matching-ns/matching-workload[Deployment] | All Connections |
| matching-ns/matching-workload[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| matching-ns/matching-workload[Deployment] | hello-world/workload-a[Deployment] | All Connections |
## Exposure Analysis Result:
### Egress Exposure:
| src | dst | conn |
|-----|-----|------|
| matching-ns/matching-workload[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| matching-ns/matching-workload[Deployment] | entire-cluster | All Connections |

### Ingress Exposure:
| dst | src | conn |
|-----|-----|------|
| hello-world/workload-a[Deployment] | [namespace with {{Key:env,Operator:In,Values:[env-1 env-2],},{Key:tier,Operator:Exists,Values:[],}}]/[all pods] | All Connections |
| matching-ns/matching-workload[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| matching-ns/matching-workload[Deployment] | entire-cluster | All Connections |