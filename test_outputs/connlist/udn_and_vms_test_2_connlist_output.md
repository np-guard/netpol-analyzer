| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255[External] | blue[udn]/vm-a[VirtualMachine] | All Connections |
| 0.0.0.0-255.255.255.255[External] | green[udn]/vm-a[VirtualMachine] | TCP 9001 |
| 0.0.0.0-255.255.255.255[External] | green[udn]/vm-b[VirtualMachine] | TCP 9001 |
| 0.0.0.0-255.255.255.255[External] | green[udn]/webserver[Pod] | TCP 9001 |
| blue[udn]/vm-a[VirtualMachine] | 0.0.0.0-255.255.255.255[External] | All Connections |
| green[udn]/vm-a[VirtualMachine] | 0.0.0.0-255.255.255.255[External] | All Connections |
| green[udn]/vm-a[VirtualMachine] | green[udn]/vm-b[VirtualMachine] | TCP 9001 |
| green[udn]/vm-a[VirtualMachine] | green[udn]/webserver[Pod] | TCP 9001 |
| green[udn]/vm-b[VirtualMachine] | 0.0.0.0-255.255.255.255[External] | All Connections |
| green[udn]/vm-b[VirtualMachine] | green[udn]/vm-a[VirtualMachine] | TCP 9001 |
| green[udn]/vm-b[VirtualMachine] | green[udn]/webserver[Pod] | TCP 9001 |
| green[udn]/webserver[Pod] | 0.0.0.0-255.255.255.255[External] | All Connections |
| green[udn]/webserver[Pod] | green[udn]/vm-a[VirtualMachine] | TCP 9001 |
| green[udn]/webserver[Pod] | green[udn]/vm-b[VirtualMachine] | TCP 9001 |
