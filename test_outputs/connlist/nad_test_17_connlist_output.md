| src | dst | conn | network | 
|-----|-----|------|------|
| test-ipblock/pod-client-a[Pod] | test-ipblock/pod-client-b[Pod] | All Connections | macvlan1-ipblock | 
| test-ipblock/pod-client-a[Pod] | test-ipblock/pod-client-c[Pod] | All Connections | macvlan1-ipblock | 
| test-ipblock/pod-client-a[Pod] | test-ipblock/pod-server[Pod] | All Connections | macvlan1-ipblock | 
| test-ipblock/pod-client-b[Pod] | test-ipblock/pod-client-a[Pod] | All Connections | macvlan1-ipblock | 
| test-ipblock/pod-client-b[Pod] | test-ipblock/pod-client-c[Pod] | All Connections | macvlan1-ipblock | 
| test-ipblock/pod-client-b[Pod] | test-ipblock/pod-server[Pod] | All Connections | macvlan1-ipblock | 
| test-ipblock/pod-client-c[Pod] | test-ipblock/pod-client-a[Pod] | All Connections | macvlan1-ipblock | 
| test-ipblock/pod-client-c[Pod] | test-ipblock/pod-client-b[Pod] | All Connections | macvlan1-ipblock | 
| test-ipblock/pod-server[Pod] | test-ipblock/pod-client-a[Pod] | All Connections | macvlan1-ipblock | 
| test-ipblock/pod-server[Pod] | test-ipblock/pod-client-b[Pod] | All Connections | macvlan1-ipblock | 
| test-ipblock/pod-server[Pod] | test-ipblock/pod-client-c[Pod] | All Connections | macvlan1-ipblock | 
