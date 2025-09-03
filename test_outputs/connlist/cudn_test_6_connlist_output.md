| src | dst | conn | network | 
|-----|-----|------|------|
| 0.0.0.0-255.255.255.255[External] | default/app-default[StatefulSet] | All Connections | pod-network | 
| 0.0.0.0-255.255.255.255[External] | green/app-green[StatefulSet] | All Connections | colored-bg | 
| 0.0.0.0-255.255.255.255[External] | red/app-red[StatefulSet] | All Connections | colored-ry | 
| 0.0.0.0-255.255.255.255[External] | yellow/app-yellow[StatefulSet] | All Connections | colored-ry | 
| blue/app-blue[StatefulSet] | green/app-green[StatefulSet] | TCP 9090 | colored-bg | 
| default/app-default[StatefulSet] | 0.0.0.0-255.255.255.255[External] | All Connections | pod-network | 
| green/app-green[StatefulSet] | 0.0.0.0-255.255.255.255[External] | All Connections | colored-bg | 
| green/app-green[StatefulSet] | blue/app-blue[StatefulSet] | TCP 8000 | colored-bg | 
| red/app-red[StatefulSet] | yellow/app-yellow[StatefulSet] | TCP 8080 | colored-ry | 
| yellow/app-yellow[StatefulSet] | 0.0.0.0-255.255.255.255[External] | All Connections | colored-ry | 
| yellow/app-yellow[StatefulSet] | red/app-red[StatefulSet] | All Connections | colored-ry | 
