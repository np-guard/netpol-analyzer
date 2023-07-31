| source | destination | dir1 | dir2 | diff-type |
|--------|-------------|------|------|-----------|
| default/checkoutservice[Deployment] | default/cartservice[Deployment] | TCP 7070 | TCP 8000 | changed |
| default/checkoutservice[Deployment] | default/emailservice[Deployment] | TCP 8080 | TCP 8080,9555 | changed |
| default/cartservice[Deployment] | default/emailservice[Deployment] | No Connections | TCP 9555 | added |
| default/checkoutservice[Deployment] | default/adservice[Deployment] | No Connections | TCP 9555 | added |
| 128.0.0.0-255.255.255.255 | default/redis-cart[Deployment] | All Connections | No Connections | removed |
| default/checkoutservice[Deployment] | default/currencyservice[Deployment] | TCP 7000 | No Connections | removed |
| default/frontend[Deployment] | default/adservice[Deployment] | TCP 9555 | No Connections | removed |
| default/redis-cart[Deployment] | 0.0.0.0-127.255.255.255 | All Connections | No Connections | removed |
| default/redis-cart[Deployment] | 128.0.0.0-255.255.255.255 | All Connections | No Connections | removed |