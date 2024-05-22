| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255 | backend/backend-app[Deployment] | All Connections |
## Exposure Analysis Result:
| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255 | backend/backend-app[Deployment] | All Connections |
| backend/[all pods] | hello-world/workload-a[Deployment] | TCP 8050 |
| entire-cluster | backend/backend-app[Deployment] | All Connections |