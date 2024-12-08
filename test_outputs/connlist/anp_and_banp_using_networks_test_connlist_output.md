| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255 | ns1/pod1[Deployment] | All Connections |
| 0.0.0.0-255.255.255.255 | ns2/pod1[Deployment] | All Connections |
| ns1/pod1[Deployment] | 10.0.0.0-10.255.255.255 | UDP 53 |
| ns1/pod1[Deployment] | 60.45.72.0-60.45.75.255 | All Connections |
| ns1/pod1[Deployment] | 89.246.180.0-89.246.183.255 | All Connections |
| ns1/pod1[Deployment] | ns2/pod1[Deployment] | All Connections |
| ns2/pod1[Deployment] | 60.45.72.0-60.45.75.255 | All Connections |
| ns2/pod1[Deployment] | 89.246.180.0-89.246.183.255 | All Connections |
| ns2/pod1[Deployment] | ns1/pod1[Deployment] | All Connections |
