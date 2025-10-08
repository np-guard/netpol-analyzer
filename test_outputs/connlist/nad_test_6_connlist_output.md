| src | dst | conn | network | 
|-----|-----|------|------|
| test-simple-v4-ingress/pod-client-a[Pod] | test-simple-v4-ingress/pod-client-b[Pod] | All Connections | macvlan1-simple | 
| test-simple-v4-ingress/pod-client-a[Pod] | test-simple-v4-ingress/pod-server[Pod] | All Connections | macvlan1-simple | 
| test-simple-v4-ingress/pod-client-b[Pod] | test-simple-v4-ingress/pod-client-a[Pod] | All Connections | macvlan1-simple | 
| test-simple-v4-ingress/pod-server[Pod] | test-simple-v4-ingress/pod-client-a[Pod] | All Connections | macvlan1-simple | 
| test-simple-v4-ingress/pod-server[Pod] | test-simple-v4-ingress/pod-client-b[Pod] | All Connections | macvlan1-simple | 
