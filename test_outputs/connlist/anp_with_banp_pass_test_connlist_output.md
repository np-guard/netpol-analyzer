| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255[External] | ns1/pod1[Deployment] | All Connections |
| 0.0.0.0-255.255.255.255[External] | ns2/pod1[Deployment] | All Connections |
| ns1/pod1[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| ns1/pod1[Deployment] | ns2/pod1[Deployment] | All Connections |
| ns2/pod1[Deployment] | 0.0.0.0-255.255.255.255[External] | All Connections |
| ns2/pod1[Deployment] | ns1/pod1[Deployment] | SCTP 1-65535,TCP 1-65535,UDP 1-79,81-65535 |
