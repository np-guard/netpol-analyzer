| src | dst | conn | network | 
|-----|-----|------|------|
| 0.0.0.0-255.255.255.255[External] | blue-namespace/blue[VirtualMachine] | All Connections | entire-cluster-cudn | 
| 0.0.0.0-255.255.255.255[External] | green-namespace/green[VirtualMachine] | All Connections | entire-cluster-cudn | 
| 0.0.0.0-255.255.255.255[External] | red-namespace/red[VirtualMachine] | All Connections | entire-cluster-cudn | 
| 0.0.0.0-255.255.255.255[External] | yellow-namespace/yellow[VirtualMachine] | All Connections | pod_network | 
| blue-namespace/blue[VirtualMachine] | 0.0.0.0-255.255.255.255[External] | All Connections | entire-cluster-cudn | 
| blue-namespace/blue[VirtualMachine] | green-namespace/green[VirtualMachine] | All Connections | entire-cluster-cudn | 
| blue-namespace/blue[VirtualMachine] | red-namespace/red[VirtualMachine] | All Connections | entire-cluster-cudn | 
| green-namespace/green[VirtualMachine] | 0.0.0.0-255.255.255.255[External] | All Connections | entire-cluster-cudn | 
| green-namespace/green[VirtualMachine] | blue-namespace/blue[VirtualMachine] | All Connections | entire-cluster-cudn | 
| green-namespace/green[VirtualMachine] | red-namespace/red[VirtualMachine] | All Connections | entire-cluster-cudn | 
| red-namespace/red[VirtualMachine] | 0.0.0.0-255.255.255.255[External] | All Connections | entire-cluster-cudn | 
| red-namespace/red[VirtualMachine] | blue-namespace/blue[VirtualMachine] | All Connections | entire-cluster-cudn | 
| red-namespace/red[VirtualMachine] | green-namespace/green[VirtualMachine] | All Connections | entire-cluster-cudn | 
| yellow-namespace/yellow[VirtualMachine] | 0.0.0.0-255.255.255.255[External] | All Connections | pod_network | 
