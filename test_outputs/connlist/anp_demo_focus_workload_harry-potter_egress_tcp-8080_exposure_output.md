| src | dst |
|-----|-----|
| gryffindor/harry-potter[StatefulSet] | 0.0.0.0-255.255.255.255 |
| gryffindor/harry-potter[StatefulSet] | hufflepuff/cedric-diggory[StatefulSet] |
| gryffindor/harry-potter[StatefulSet] | slytherin/draco-malfoy[StatefulSet] |
## Exposure Analysis Result On TCP 8080:
### Egress Exposure:
| src | dst |
|-----|-----|
| gryffindor/harry-potter[StatefulSet] | 0.0.0.0-255.255.255.255 |
| gryffindor/harry-potter[StatefulSet] | entire-cluster |

