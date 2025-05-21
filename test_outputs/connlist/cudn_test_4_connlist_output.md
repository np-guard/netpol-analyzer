| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255[External] | udn-example[udn]/example-vm[VirtualMachine] | All Connections |
| 0.0.0.0-255.255.255.255[External] | udn-preprod/vm-preprod[VirtualMachine] | All Connections |
| 0.0.0.0-255.255.255.255[External] | udn-prod/vm-prod[VirtualMachine] | All Connections |
| udn-example[udn]/example-vm[VirtualMachine] | 0.0.0.0-255.255.255.255[External] | All Connections |
| udn-preprod/vm-preprod[VirtualMachine] | 0.0.0.0-255.255.255.255[External] | All Connections |
| udn-preprod/vm-preprod[VirtualMachine] | udn-prod/vm-prod[VirtualMachine] | All Connections |
| udn-prod/vm-prod[VirtualMachine] | 0.0.0.0-255.255.255.255[External] | All Connections |
| udn-prod/vm-prod[VirtualMachine] | udn-preprod/vm-preprod[VirtualMachine] | All Connections |
