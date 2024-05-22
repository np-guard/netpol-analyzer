| src | dst | conn |
|-----|-----|------|
| default/loadgenerator[Deployment] | default/frontend[Deployment] | TCP 8080 |
## Exposure Analysis Result:
| src | dst | conn |
|-----|-----|------|
| default/loadgenerator[Deployment] | [all namespaces]/[pod with {k8s-app=kube-dns}] | UDP 53 |