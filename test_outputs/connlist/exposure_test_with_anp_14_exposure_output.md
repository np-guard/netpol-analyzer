| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255 | hello-world/workload-a[Deployment] | All Connections |
| 0.0.0.0-255.255.255.255 | hello-world/workload-b[Deployment] | All Connections |
| hello-world/workload-a[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| hello-world/workload-b[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
## Exposure Analysis Result:
### Egress Exposure:
| src | dst | conn |
|-----|-----|------|
| hello-world/workload-a[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| hello-world/workload-a[Deployment] | [namespace with {foo=managed,{Key:app,Operator:DoesNotExist,Values:[],},{Key:env,Operator:Exists,Values:[],}}]/[pod with {app=app-x,{Key:role,Operator:NotIn,Values:[monitoring search web],}}] | All Connections |

### Ingress Exposure:
| dst | src | conn |
|-----|-----|------|
| hello-world/workload-a[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| hello-world/workload-a[Deployment] | [namespace with {foo=managed,{Key:app,Operator:DoesNotExist,Values:[],},{Key:env,Operator:Exists,Values:[],}}]/[pod with {app=app-x,{Key:role,Operator:NotIn,Values:[monitoring search web],}}] | All Connections |
