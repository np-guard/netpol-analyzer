| src | dst | conn |
|-----|-----|------|
| default/frontend[Deployment] | default/backend[Deployment] | TCP 9090 |
## Exposure Analysis Result:

### Ingress Exposure:
| dst | src | conn |
|-----|-----|------|
| default/backend[Deployment] | [all namespaces]/[pod with {app=frontend}] | TCP 9090 |
