| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255[External] | blue/webserver[Pod] | All Connections |
| 0.0.0.0-255.255.255.255[External] | green/webserver-2[Pod] | TCP 9001 |
| 0.0.0.0-255.255.255.255[External] | green/webserver[Pod] | TCP 9001 |
| blue/webserver[Pod] | 0.0.0.0-255.255.255.255[External] | All Connections |
| green/webserver-2[Pod] | 0.0.0.0-255.255.255.255[External] | All Connections |
| green/webserver-2[Pod] | green/webserver[Pod] | TCP 9001 |
| green/webserver[Pod] | 0.0.0.0-255.255.255.255[External] | All Connections |
| green/webserver[Pod] | green/webserver-2[Pod] | TCP 9001 |
