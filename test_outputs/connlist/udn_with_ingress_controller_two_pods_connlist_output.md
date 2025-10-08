| src | dst | conn | network | 
|-----|-----|------|------|
| 0.0.0.0-255.255.255.255[External] | green[udn]/app[Pod] | All Connections | green | 
| 0.0.0.0-255.255.255.255[External] | green[udn]/db[Pod] | All Connections | green | 
| green[udn]/app[Pod] | 0.0.0.0-255.255.255.255[External] | All Connections | green | 
| green[udn]/app[Pod] | green[udn]/db[Pod] | All Connections | green | 
| green[udn]/db[Pod] | 0.0.0.0-255.255.255.255[External] | All Connections | green | 
| green[udn]/db[Pod] | green[udn]/app[Pod] | All Connections | green | 
| {ingress-controller} | green[udn]/app[Pod] | TCP 8000,8090 | green | 
