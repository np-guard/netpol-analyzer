| diff-type | source | destination | ref1 | ref2 | workloads-diff-info |
|-----------|--------|-------------|------|------|---------------------|
| changed | backend/reports[Deployment] | backend/catalog[Deployment] | TCP 8080 | TCP 9080 |  |
| added | 0.0.0.0-255.255.255.255[External] | external/unicorn[Deployment] | No Connections | All Connections | workload external/unicorn[Deployment] added |
| added | backend/checkout[Deployment] | external/unicorn[Deployment] | No Connections | UDP 5353 | workload external/unicorn[Deployment] added |
| added | backend/recommendation[Deployment] | external/unicorn[Deployment] | No Connections | UDP 5353 | workload external/unicorn[Deployment] added |
| added | backend/reports[Deployment] | external/unicorn[Deployment] | No Connections | UDP 5353 | workload external/unicorn[Deployment] added |
| added | external/unicorn[Deployment] | 0.0.0.0-255.255.255.255[External] | No Connections | All Connections | workload external/unicorn[Deployment] added |
| added | external/unicorn[Deployment] | frontend/webapp[Deployment] | No Connections | TCP 8080 | workload external/unicorn[Deployment] added |
| added | frontend/webapp[Deployment] | external/unicorn[Deployment] | No Connections | UDP 5353 | workload external/unicorn[Deployment] added |
| added | payments/gateway[Deployment] | external/unicorn[Deployment] | No Connections | UDP 5353 | workload external/unicorn[Deployment] added |
| removed | frontend/webapp[Deployment] | backend/shipping[Deployment] | TCP 8080 | No Connections |  |
| removed | payments/gateway[Deployment] | payments/mastercard-processor[Deployment] | TCP 8080 | No Connections | workload payments/mastercard-processor[Deployment] removed |
| removed | {ingress-controller} | frontend/asset-cache[Deployment] | TCP 8080 | No Connections |  |