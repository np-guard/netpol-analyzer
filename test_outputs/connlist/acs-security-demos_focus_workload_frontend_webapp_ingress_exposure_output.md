| src | dst | conn |
|-----|-----|------|
| {ingress-controller} | frontend/webapp[Deployment] | TCP 8080 |
## Exposure Analysis Result:

### Ingress Exposure:
| dst | src | conn |
|-----|-----|------|
| frontend/webapp[Deployment] | entire-cluster | TCP 8080 |
