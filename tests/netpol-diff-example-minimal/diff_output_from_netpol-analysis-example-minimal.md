| source | destination | dir1 | dir2 | diff-type |
|--------|-------------|------|------|-----------|
| default/frontend[Deployment] | default/backend[Deployment] | TCP 9090 | TCP 9090,UDP 53 | changed |
| 0.0.0.0-255.255.255.255 | default/backend[Deployment] | No Connections | TCP 9090 | added |