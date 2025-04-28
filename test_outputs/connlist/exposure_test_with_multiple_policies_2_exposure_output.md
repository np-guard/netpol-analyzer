| src | dst | conn |
|-----|-----|------|
| hello-world/workload-a[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
## Exposure Analysis Result:
### Egress Exposure:
| src | dst | conn |
|-----|-----|------|
| hello-world/workload-a[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| hello-world/workload-a[Deployment] | entire-cluster | All Connections |

### Ingress Exposure:
| dst | src | conn |
|-----|-----|------|
| hello-world/workload-a[Deployment] | [namespace with {{Key:env,Operator:In,Values:[env-1 env-2],},{Key:tier,Operator:Exists,Values:[],}}]/[all pods] | TCP 8050 |
| hello-world/workload-b[Deployment] | [namespace with {{Key:env,Operator:In,Values:[env-1 env-2],},{Key:tier,Operator:Exists,Values:[],}}]/[all pods] | All Connections |
