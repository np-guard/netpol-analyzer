| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255[External] | hello-world/workload-a[Deployment] | All Connections |
## Exposure Analysis Result:

### Ingress Exposure:
| dst | src | conn |
|-----|-----|------|
| hello-world/workload-a[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| hello-world/workload-a[Deployment] | entire-cluster | All Connections |
