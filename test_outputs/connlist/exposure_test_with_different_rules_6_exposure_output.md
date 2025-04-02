| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255[External] | hello-world/workload-b[Deployment] | All Connections |
| hello-world/workload-a[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| hello-world/workload-a[Deployment] | hello-world/workload-b[Deployment] | All Connections |
| hello-world/workload-b[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
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
| hello-world/workload-a[Deployment] | [namespace with {env=env-1,foo=managed}]/[pod with {app=app-x,{Key:role,Operator:In,Values:[api],}}] | TCP 8080 |
| hello-world/workload-a[Deployment] | [namespace with {foo=managed,{Key:app,Operator:DoesNotExist,Values:[],},{Key:env,Operator:Exists,Values:[],}}]/[pod with {app=app-x,{Key:role,Operator:NotIn,Values:[monitoring search web],}}] | TCP 9090 |
| hello-world/workload-b[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| hello-world/workload-b[Deployment] | entire-cluster | All Connections |
