| src | dst | conn | network | 
|-----|-----|------|------|
| 0.0.0.0-255.255.255.255[External] | blue[udn]/vm-a[VirtualMachine] | All Connections | blue | 
| 0.0.0.0-255.255.255.255[External] | green[udn]/vm-a[VirtualMachine] | All Connections | green | 
| 0.0.0.0-255.255.255.255[External] | green[udn]/vm-b[VirtualMachine] | All Connections | green | 
| 0.0.0.0-255.255.255.255[External] | green[udn]/webserver[Pod] | All Connections | green | 
| blue[udn]/vm-a[VirtualMachine] | 0.0.0.0-255.255.255.255[External] | All Connections | blue | 
| green[udn]/vm-a[VirtualMachine] | 0.0.0.0-255.255.255.255[External] | All Connections | green | 
| green[udn]/vm-a[VirtualMachine] | green[udn]/vm-b[VirtualMachine] | All Connections | green | 
| green[udn]/vm-a[VirtualMachine] | green[udn]/webserver[Pod] | All Connections | green | 
| green[udn]/vm-b[VirtualMachine] | 0.0.0.0-255.255.255.255[External] | All Connections | green | 
| green[udn]/vm-b[VirtualMachine] | green[udn]/vm-a[VirtualMachine] | All Connections | green | 
| green[udn]/vm-b[VirtualMachine] | green[udn]/webserver[Pod] | All Connections | green | 
| green[udn]/webserver[Pod] | 0.0.0.0-255.255.255.255[External] | All Connections | green | 
| green[udn]/webserver[Pod] | green[udn]/vm-a[VirtualMachine] | All Connections | green | 
| green[udn]/webserver[Pod] | green[udn]/vm-b[VirtualMachine] | All Connections | green | 
