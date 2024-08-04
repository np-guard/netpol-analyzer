| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255 | backend/backend-app[Deployment] | All Connections |
## Exposure Analysis Result:

### Ingress Exposure:
| dst | src | conn |
|-----|-----|------|
| backend/backend-app[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| backend/backend-app[Deployment] | entire-cluster | All Connections |
| hello-world/workload-a[Deployment] | backend/[all pods] | TCP 8050 |
