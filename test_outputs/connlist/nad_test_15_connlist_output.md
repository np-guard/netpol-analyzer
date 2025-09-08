| src | dst | conn | network | 
|-----|-----|------|------|
| bond-testing/pod-a[Pod] | bond-testing/pod-b[Pod] | All Connections | macvlan-nad | 
| bond-testing/pod-a[Pod] | bond-testing/pod-c[Pod] | All Connections | bond-nad | 
| bond-testing/pod-a[Pod] | bond-testing/pod-c[Pod] | All Connections | macvlan-nad | 
| bond-testing/pod-b[Pod] | bond-testing/pod-a[Pod] | All Connections | bond-nad | 
| bond-testing/pod-b[Pod] | bond-testing/pod-a[Pod] | All Connections | macvlan-nad | 
| bond-testing/pod-b[Pod] | bond-testing/pod-c[Pod] | All Connections | bond-nad | 
| bond-testing/pod-b[Pod] | bond-testing/pod-c[Pod] | All Connections | macvlan-nad | 
| bond-testing/pod-c[Pod] | bond-testing/pod-a[Pod] | All Connections | macvlan-nad | 
| bond-testing/pod-c[Pod] | bond-testing/pod-b[Pod] | All Connections | bond-nad | 
| bond-testing/pod-c[Pod] | bond-testing/pod-b[Pod] | All Connections | macvlan-nad | 
