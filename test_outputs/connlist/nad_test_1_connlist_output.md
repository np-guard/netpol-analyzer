| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255[External] | default/dns-app[Deployment] | All Connections |
| 0.0.0.0-255.255.255.255[External] | default/nginx-app[Deployment] | All Connections |
| 0.0.0.0-255.255.255.255[External] | default/router-app[Deployment] | All Connections |
| default/dns-app[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| default/dns-app[Deployment] | default/nginx-app[Deployment] | All Connections |
| default/dns-app[Deployment] | default/router-app[Deployment] | All Connections |
| default/nginx-app[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| default/nginx-app[Deployment] | default/dns-app[Deployment] | All Connections |
| default/nginx-app[Deployment] | default/router-app[Deployment] | All Connections |
| default/router-app[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| default/router-app[Deployment] | default/dns-app[Deployment] | All Connections |
| default/router-app[Deployment] | default/nginx-app[Deployment] | All Connections |
