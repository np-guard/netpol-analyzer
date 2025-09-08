| src | dst | conn | network | 
|-----|-----|------|------|
| 0.0.0.0-255.255.255.255[External] | blue-namespace/blue[VirtualMachine] | All Connections | happy-tenant | 
| 0.0.0.0-255.255.255.255[External] | green-namespace/green[VirtualMachine] | All Connections | pod_network | 
| 0.0.0.0-255.255.255.255[External] | red-namespace/red[VirtualMachine] | All Connections | happy-tenant | 
| 0.0.0.0-255.255.255.255[External] | yellow-namespace/yellow[VirtualMachine] | All Connections | pod_network | 
| blue-namespace/blue[VirtualMachine] | 0.0.0.0-255.255.255.255[External] | All Connections | happy-tenant | 
| blue-namespace/blue[VirtualMachine] | red-namespace/red[VirtualMachine] | All Connections | happy-tenant | 
| green-namespace/green[VirtualMachine] | 0.0.0.0-255.255.255.255[External] | All Connections | pod_network | 
| green-namespace/green[VirtualMachine] | yellow-namespace/yellow[VirtualMachine] | All Connections | pod_network | 
| red-namespace/red[VirtualMachine] | 0.0.0.0-255.255.255.255[External] | All Connections | happy-tenant | 
| red-namespace/red[VirtualMachine] | blue-namespace/blue[VirtualMachine] | All Connections | happy-tenant | 
| yellow-namespace/yellow[VirtualMachine] | 0.0.0.0-255.255.255.255[External] | All Connections | pod_network | 
| yellow-namespace/yellow[VirtualMachine] | green-namespace/green[VirtualMachine] | All Connections | pod_network | 
