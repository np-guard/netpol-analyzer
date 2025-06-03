| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255[External] | default/app-default[StatefulSet] | All Connections |
| 0.0.0.0-255.255.255.255[External] | green/app-green[StatefulSet] | All Connections |
| 0.0.0.0-255.255.255.255[External] | red/app-red[StatefulSet] | All Connections |
| 0.0.0.0-255.255.255.255[External] | yellow/app-yellow[StatefulSet] | All Connections |
| blue/app-blue[StatefulSet] | green/app-green[StatefulSet] | TCP 9090 |
| default/app-default[StatefulSet] | 0.0.0.0-255.255.255.255[External] | All Connections |
| green/app-green[StatefulSet] | 0.0.0.0-255.255.255.255[External] | All Connections |
| green/app-green[StatefulSet] | blue/app-blue[StatefulSet] | TCP 8000 |
| red/app-red[StatefulSet] | yellow/app-yellow[StatefulSet] | TCP 8080 |
| yellow/app-yellow[StatefulSet] | 0.0.0.0-255.255.255.255[External] | All Connections |
| yellow/app-yellow[StatefulSet] | red/app-red[StatefulSet] | All Connections |
