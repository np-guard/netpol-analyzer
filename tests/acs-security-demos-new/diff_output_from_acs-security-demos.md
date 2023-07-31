| source | destination | dir1 | dir2 | diff-type |
|--------|-------------|------|------|-----------|
| backend/reports[Deployment] | backend/catalog[Deployment] | TCP 8080 | TCP 9080 | changed |
| 0.0.0.0-255.255.255.255 | external/unicorn[Deployment] | No Connections | All Connections | added |
| backend/checkout[Deployment] | external/unicorn[Deployment] | No Connections | UDP 5353 | added |
| backend/recommendation[Deployment] | external/unicorn[Deployment] | No Connections | UDP 5353 | added |
| backend/reports[Deployment] | external/unicorn[Deployment] | No Connections | UDP 5353 | added |
| external/unicorn[Deployment] | 0.0.0.0-255.255.255.255 | No Connections | All Connections | added |
| external/unicorn[Deployment] | frontend/webapp[Deployment] | No Connections | TCP 8080 | added |
| frontend/webapp[Deployment] | external/unicorn[Deployment] | No Connections | UDP 5353 | added |
| payments/gateway[Deployment] | external/unicorn[Deployment] | No Connections | UDP 5353 | added |
| frontend/webapp[Deployment] | backend/shipping[Deployment] | TCP 8080 | No Connections | removed |
| payments/gateway[Deployment] | payments/mastercard-processor[Deployment] | TCP 8080 | No Connections | removed |
| {ingress-controller} | frontend/asset-cache[Deployment] | TCP 8080 | No Connections | removed |