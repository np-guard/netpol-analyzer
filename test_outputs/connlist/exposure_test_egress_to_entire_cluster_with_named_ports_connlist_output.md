| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255 | hello-world/workload-a[Deployment] | All Connections |
## Exposure Analysis Result:
| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255 | hello-world/workload-a[Deployment] | All Connections |
| entire-cluster | hello-world/workload-a[Deployment] | All Connections |
| hello-world/workload-a[Deployment] | entire-cluster | TCP http,local-dns |