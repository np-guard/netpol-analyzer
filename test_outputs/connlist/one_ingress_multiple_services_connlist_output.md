| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255 | ingressworld/ingress-world-multiple-ports[Deployment] | All Connections |
| ingressworld/ingress-world-multiple-ports[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| {ingress-nginx} | ingressworld/ingress-world-multiple-ports[Deployment] | TCP 8000,8090 |
| {openshift-ingress-operator} | ingressworld/ingress-world-multiple-ports[Deployment] | TCP 8000,8090 |