| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255 | default/frontend[Deployment] | TCP 8080 |
| default/frontend[Deployment] | 0.0.0.0-255.255.255.255 | UDP 53 |
| default/frontend[Deployment] | default/backend[Deployment] | TCP 9090 |
