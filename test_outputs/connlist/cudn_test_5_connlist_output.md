| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255[External] | blue[udn]/app-blue[StatefulSet] | All Connections |
| 0.0.0.0-255.255.255.255[External] | default/app-default[StatefulSet] | All Connections |
| 0.0.0.0-255.255.255.255[External] | green[udn]/app-green[StatefulSet] | All Connections |
| 0.0.0.0-255.255.255.255[External] | red/app-red[StatefulSet] | All Connections |
| 0.0.0.0-255.255.255.255[External] | yellow/app-yellow[StatefulSet] | All Connections |
| blue[udn]/app-blue[StatefulSet] | 0.0.0.0-255.255.255.255[External] | All Connections |
| default/app-default[StatefulSet] | 0.0.0.0-255.255.255.255[External] | All Connections |
| green[udn]/app-green[StatefulSet] | 0.0.0.0-255.255.255.255[External] | All Connections |
| red/app-red[StatefulSet] | yellow/app-yellow[StatefulSet] | TCP 8080 |
| yellow/app-yellow[StatefulSet] | 0.0.0.0-255.255.255.255[External] | All Connections |
| yellow/app-yellow[StatefulSet] | red/app-red[StatefulSet] | All Connections |
