| src | dst | conn |
|-----|-----|------|
| hello-world/workload-a[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
## Exposure Analysis Result:
| src | dst | conn |
|-----|-----|------|
| entire-cluster | hello-world/workload-a[Deployment] | TCP 8000,8090 |
| hello-world/workload-a[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| hello-world/workload-a[Deployment] | entire-cluster | All Connections |