| source | destination | dir1 | dir2 | diff-type |
|--------|-------------|------|------|-----------|
| payments/gateway[Deployment] | payments/visa-processor-v2[Deployment] | No Connections | TCP 8080 | added (workload payments/visa-processor-v2[Deployment] added) |
| {ingress-controller} | frontend/blog[Deployment] | No Connections | TCP 8080 | added (workload frontend/blog[Deployment] added) |
| {ingress-controller} | zeroday/zeroday[Deployment] | No Connections | TCP 8080 | added (workload zeroday/zeroday[Deployment] added) |