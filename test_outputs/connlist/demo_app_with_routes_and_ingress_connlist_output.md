| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255 | helloworld/hello-world[Deployment] | All Connections |
| 0.0.0.0-255.255.255.255 | ingressworld/ingress-world[Deployment] | All Connections |
| 0.0.0.0-255.255.255.255 | routeworld/route-world[Deployment] | All Connections |
| helloworld/hello-world[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| helloworld/hello-world[Deployment] | ingressworld/ingress-world[Deployment] | All Connections |
| helloworld/hello-world[Deployment] | routeworld/route-world[Deployment] | All Connections |
| ingressworld/ingress-world[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| ingressworld/ingress-world[Deployment] | helloworld/hello-world[Deployment] | All Connections |
| ingressworld/ingress-world[Deployment] | routeworld/route-world[Deployment] | All Connections |
| routeworld/route-world[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| routeworld/route-world[Deployment] | helloworld/hello-world[Deployment] | All Connections |
| routeworld/route-world[Deployment] | ingressworld/ingress-world[Deployment] | All Connections |
| {ingress-controller} | helloworld/hello-world[Deployment] | TCP 8000 |
| {ingress-controller} | ingressworld/ingress-world[Deployment] | TCP 8090 |
| {ingress-controller} | routeworld/route-world[Deployment] | TCP 8060 |
