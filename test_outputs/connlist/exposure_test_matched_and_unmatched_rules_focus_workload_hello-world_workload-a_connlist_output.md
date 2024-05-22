| src | dst | conn |
|-----|-----|------|
| hello-world/workload-a[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| hello-world/workload-a[Deployment] | hello-world/workload-b[Deployment] | All Connections |
| hello-world/workload-b[Deployment] | hello-world/workload-a[Deployment] | All Connections |
## Exposure Analysis Result:
| src | dst | conn |
|-----|-----|------|
| entire-cluster | hello-world/workload-a[Deployment] | TCP 8050 |
| hello-world/workload-a[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| hello-world/workload-a[Deployment] | entire-cluster | All Connections |