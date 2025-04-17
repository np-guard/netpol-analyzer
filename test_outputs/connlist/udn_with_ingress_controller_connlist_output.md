| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255[External] | green[udn]/pod1[Pod] | All Connections |
| green[udn]/pod1[Pod] | 0.0.0.0-255.255.255.255[External] | All Connections |
| {ingress-controller} | green[udn]/pod1[Pod] | TCP 8000,8090 |
