| src | dst | conn |
|-----|-----|------|
## Exposure Analysis Result:

### Ingress Exposure:
| dst | src | conn |
|-----|-----|------|
| hello-world/workload-a[Deployment] | [namespace with {{Key:env,Operator:In,Values:[env-1 env-2],},{Key:tier,Operator:Exists,Values:[],}}]/[all pods] | All Connections |
