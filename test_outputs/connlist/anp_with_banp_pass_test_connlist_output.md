| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255 | ns1/pod1[Deployment] | All Connections |
| 0.0.0.0-255.255.255.255 | ns2/pod1[Deployment] | All Connections |
| ns1/pod1[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| ns1/pod1[Deployment] | ns2/pod1[Deployment] | All Connections |
| ns2/pod1[Deployment] | 0.0.0.0-255.255.255.255 | All Connections |
| ns2/pod1[Deployment] | ns1/pod1[Deployment] | All but: UDP 80 |
