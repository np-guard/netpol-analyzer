| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255 | bar/my-bar[Pod] | All Connections |
| 0.0.0.0-255.255.255.255 | baz/my-baz[Pod] | All Connections |
| 0.0.0.0-255.255.255.255 | monitoring/my-monitoring[Pod] | All Connections |
| bar/my-bar[Pod] | 0.0.0.0-255.255.255.255 | All Connections |
| bar/my-bar[Pod] | baz/my-baz[Pod] | All Connections |
| bar/my-bar[Pod] | monitoring/my-monitoring[Pod] | All Connections |
| baz/my-baz[Pod] | 0.0.0.0-255.255.255.255 | All Connections |
| baz/my-baz[Pod] | monitoring/my-monitoring[Pod] | All Connections |
| foo/my-foo[Pod] | 0.0.0.0-255.255.255.255 | All Connections |
| foo/my-foo[Pod] | baz/my-baz[Pod] | All Connections |
| foo/my-foo[Pod] | monitoring/my-monitoring[Pod] | All Connections |
| monitoring/my-monitoring[Pod] | 0.0.0.0-255.255.255.255 | All Connections |
| monitoring/my-monitoring[Pod] | baz/my-baz[Pod] | All Connections |
| monitoring/my-monitoring[Pod] | foo/my-foo[Pod] | All Connections |
