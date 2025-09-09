| src | dst | conn | network | 
|-----|-----|------|------|
| 0.0.0.0-255.255.255.255[External] | default/cirrus-vm-1[VirtualMachine] | TCP 9001-9090 | pod-network | 
| 0.0.0.0-255.255.255.255[External] | default/fedora-vm-1[VirtualMachine] | TCP 9001-9090 | pod-network | 
| default/cirrus-vm-1[VirtualMachine] | 0.0.0.0-255.255.255.255[External] | TCP 8080-9090 | pod-network | 
| default/cirrus-vm-1[VirtualMachine] | default/fedora-vm-1[VirtualMachine] | TCP 9001-9090 | pod-network | 
| default/fedora-vm-1[VirtualMachine] | 0.0.0.0-255.255.255.255[External] | TCP 8080-9090 | pod-network | 
| default/fedora-vm-1[VirtualMachine] | default/cirrus-vm-1[VirtualMachine] | TCP 8099,9001-9090 | pod-network | 
