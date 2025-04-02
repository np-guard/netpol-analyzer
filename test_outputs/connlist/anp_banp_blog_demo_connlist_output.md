| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255[External] | bar/mybar[Pod] | All Connections |
| 0.0.0.0-255.255.255.255[External] | baz/mybaz[Pod] | All Connections |
| 0.0.0.0-255.255.255.255[External] | monitoring/mymonitoring[Pod] | All Connections |
| bar/mybar[Pod] | 0.0.0.0-255.255.255.255[External] | All Connections |
| bar/mybar[Pod] | baz/mybaz[Pod] | All Connections |
| bar/mybar[Pod] | monitoring/mymonitoring[Pod] | All Connections |
| baz/mybaz[Pod] | 0.0.0.0-255.255.255.255[External] | All Connections |
| baz/mybaz[Pod] | monitoring/mymonitoring[Pod] | All Connections |
| foo/myfoo[Pod] | 0.0.0.0-255.255.255.255[External] | All Connections |
| foo/myfoo[Pod] | baz/mybaz[Pod] | All Connections |
| foo/myfoo[Pod] | monitoring/mymonitoring[Pod] | All Connections |
| monitoring/mymonitoring[Pod] | 0.0.0.0-255.255.255.255[External] | All Connections |
| monitoring/mymonitoring[Pod] | baz/mybaz[Pod] | All Connections |
| monitoring/mymonitoring[Pod] | foo/myfoo[Pod] | All Connections |
