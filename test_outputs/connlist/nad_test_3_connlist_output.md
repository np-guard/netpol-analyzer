| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255[External] | ns1/vm1[VirtualMachine] | All Connections |
| 0.0.0.0-255.255.255.255[External] | ns1/vm2[VirtualMachine] | All Connections |
| 0.0.0.0-255.255.255.255[External] | ns2/vm3[VirtualMachine] | All Connections |
| ns1/vm1[VirtualMachine] | 0.0.0.0-255.255.255.255[External] | All Connections |
| ns1/vm1[VirtualMachine] | ns1/vm2[VirtualMachine] | All Connections |
| ns1/vm1[VirtualMachine] | ns2/vm3[VirtualMachine] | All Connections |
| ns1/vm2[VirtualMachine] | 0.0.0.0-255.255.255.255[External] | All Connections |
| ns1/vm2[VirtualMachine] | ns1/vm1[VirtualMachine] | All Connections |
| ns2/vm3[VirtualMachine] | 0.0.0.0-255.255.255.255[External] | All Connections |
| ns2/vm3[VirtualMachine] | ns1/vm1[VirtualMachine] | All Connections |
| ns2/vm3[VirtualMachine] | ns1/vm2[VirtualMachine] | TCP 80 |
