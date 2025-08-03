| src | dst | conn | network | 
|-----|-----|------|------|
| test-protocol-only-ports/pod-a[Pod] | test-protocol-only-ports/pod-b[Pod] | TCP 1-65535 | macvlan1-simple | 
| test-protocol-only-ports/pod-b[Pod] | test-protocol-only-ports/pod-a[Pod] | UDP 1-65535 | macvlan1-simple | 
