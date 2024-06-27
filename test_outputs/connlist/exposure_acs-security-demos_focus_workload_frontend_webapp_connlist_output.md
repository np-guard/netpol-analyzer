| src | dst | conn |
|-----|-----|------|
| frontend/webapp[Deployment] | backend/checkout[Deployment] | TCP 8080 |
| frontend/webapp[Deployment] | backend/recommendation[Deployment] | TCP 8080 |
| frontend/webapp[Deployment] | backend/reports[Deployment] | TCP 8080 |
| frontend/webapp[Deployment] | backend/shipping[Deployment] | TCP 8080 |
| {ingress-controller} | frontend/webapp[Deployment] | TCP 8080 |
## Exposure Analysis Result:
### Egress Exposure:
| src | dst | conn |
|-----|-----|------|
| frontend/webapp[Deployment] | entire-cluster | UDP 5353 |

### Ingress Exposure:
| dst | src | conn |
|-----|-----|------|
| frontend/webapp[Deployment] | entire-cluster | TCP 8080 |
