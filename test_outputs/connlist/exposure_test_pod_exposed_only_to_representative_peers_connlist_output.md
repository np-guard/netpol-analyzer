| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255 | hello-world/workload-a[Deployment] | All Connections |
| hello-world/workload-a[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
## Exposure Analysis Result:
| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255 | hello-world/workload-a[Deployment] | All Connections |
| [namespace with {foo.com/managed-state=managed}]/[all pods] | hello-world/workload-b[Deployment] | TCP 8050 |
| entire-cluster | hello-world/workload-a[Deployment] | All Connections |
| hello-world/workload-a[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| hello-world/workload-a[Deployment] | entire-cluster | All Connections |
| hello-world/workload-b[Deployment] | [namespace with {foo.com/managed-state=managed}]/[all pods] | TCP 8050 |