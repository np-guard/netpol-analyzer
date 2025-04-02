| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255[External] | hello-world/workload-a[Deployment] | All Connections |
| hello-world/workload-a[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
## Exposure Analysis Result:
### Egress Exposure:
| src | dst | conn |
|-----|-----|------|
| hello-world/workload-a[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| hello-world/workload-a[Deployment] | [namespace with {conformance-house=slytherin}]/[all pods] | SCTP 1-65535,TCP 1-9089,9091-65535,UDP 1-65535 |
| hello-world/workload-a[Deployment] | entire-cluster | All Connections |

### Ingress Exposure:
| dst | src | conn |
|-----|-----|------|
| hello-world/workload-a[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| hello-world/workload-a[Deployment] | entire-cluster | All Connections |
