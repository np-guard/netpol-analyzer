| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255 | hufflepuff/cedric-diggory[StatefulSet] | All Connections |
| 0.0.0.0-255.255.255.255 | slytherin/draco-malfoy[StatefulSet] | All Connections |
| gryffindor/harry-potter[StatefulSet] | 0.0.0.0-255.255.255.255 | All Connections |
| gryffindor/harry-potter[StatefulSet] | hufflepuff/cedric-diggory[StatefulSet] | SCTP 9003,TCP 8080,UDP 5353 |
| gryffindor/harry-potter[StatefulSet] | ravenclaw/luna-lovegood[StatefulSet] | UDP 52 |
| gryffindor/harry-potter[StatefulSet] | slytherin/draco-malfoy[StatefulSet] | SCTP 1-9002,9004-65535,TCP 1-79,81-65535,UDP 1-52,54-65535 |
| hufflepuff/cedric-diggory[StatefulSet] | 0.0.0.0-255.255.255.255 | All Connections |
| hufflepuff/cedric-diggory[StatefulSet] | gryffindor/harry-potter[StatefulSet] | SCTP 9003,TCP 80,UDP 5353 |
| slytherin/draco-malfoy[StatefulSet] | 0.0.0.0-255.255.255.255 | All Connections |
| slytherin/draco-malfoy[StatefulSet] | gryffindor/harry-potter[StatefulSet] | All Connections |
| slytherin/draco-malfoy[StatefulSet] | hufflepuff/cedric-diggory[StatefulSet] | All Connections |
| slytherin/draco-malfoy[StatefulSet] | ravenclaw/luna-lovegood[StatefulSet] | TCP 1-79,81-65535 |