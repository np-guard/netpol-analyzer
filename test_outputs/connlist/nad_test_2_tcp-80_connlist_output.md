| src | dst | network |
|-----|-----|------|
| 0.0.0.0-255.255.255.255[External] | default/vm-client[VirtualMachine] | pod-network |
| 0.0.0.0-255.255.255.255[External] | default/vm-server[VirtualMachine] | pod-network |
| default/vm-client[VirtualMachine] | 0.0.0.0-255.255.255.255[External] | pod-network |
| default/vm-client[VirtualMachine] | default/vm-server[VirtualMachine] | flat12 |
| default/vm-client[VirtualMachine] | default/vm-server[VirtualMachine] | pod-network |
| default/vm-server[VirtualMachine] | 0.0.0.0-255.255.255.255[External] | pod-network |
| default/vm-server[VirtualMachine] | default/vm-client[VirtualMachine] | flat12 |
| default/vm-server[VirtualMachine] | default/vm-client[VirtualMachine] | pod-network |
