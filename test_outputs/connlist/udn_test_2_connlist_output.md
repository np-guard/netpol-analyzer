| src | dst | conn | network | 
|-----|-----|------|------|
| 0.0.0.0-255.255.255.255[External] | blue[udn]/webserver[Pod] | All Connections | blue | 
| 0.0.0.0-255.255.255.255[External] | green[udn]/webserver-2[Pod] | TCP 9001 | green | 
| 0.0.0.0-255.255.255.255[External] | green[udn]/webserver[Pod] | TCP 9001 | green | 
| blue[udn]/webserver[Pod] | 0.0.0.0-255.255.255.255[External] | All Connections | blue | 
| green[udn]/webserver-2[Pod] | 0.0.0.0-255.255.255.255[External] | All Connections | green | 
| green[udn]/webserver-2[Pod] | green[udn]/webserver[Pod] | TCP 9001 | green | 
| green[udn]/webserver[Pod] | 0.0.0.0-255.255.255.255[External] | All Connections | green | 
| green[udn]/webserver[Pod] | green[udn]/webserver-2[Pod] | TCP 9001 | green | 
