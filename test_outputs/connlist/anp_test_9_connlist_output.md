| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255[External] | network-policy-conformance-gryffindor/harry-potter[StatefulSet] | All Connections |
| 0.0.0.0-255.255.255.255[External] | network-policy-conformance-hufflepuff/cedric-diggory[StatefulSet] | All Connections |
| 0.0.0.0-255.255.255.255[External] | network-policy-conformance-ravenclaw/luna-lovegood[StatefulSet] | All Connections |
| 0.0.0.0-255.255.255.255[External] | network-policy-conformance-slytherin/draco-malfoy[StatefulSet] | All Connections |
| network-policy-conformance-gryffindor/harry-potter[StatefulSet] | 0.0.0.0-255.255.255.255[External] | All Connections |
| network-policy-conformance-gryffindor/harry-potter[StatefulSet] | network-policy-conformance-hufflepuff/cedric-diggory[StatefulSet] | SCTP 9003,TCP 8080,UDP 5353 |
| network-policy-conformance-gryffindor/harry-potter[StatefulSet] | network-policy-conformance-ravenclaw/luna-lovegood[StatefulSet] | All Connections |
| network-policy-conformance-gryffindor/harry-potter[StatefulSet] | network-policy-conformance-slytherin/draco-malfoy[StatefulSet] | SCTP 1-9002,9004-65535,TCP 1-79,81-65535,UDP 1-52,54-65535 |
| network-policy-conformance-hufflepuff/cedric-diggory[StatefulSet] | 0.0.0.0-255.255.255.255[External] | All Connections |
| network-policy-conformance-hufflepuff/cedric-diggory[StatefulSet] | network-policy-conformance-gryffindor/harry-potter[StatefulSet] | SCTP 9003,TCP 80,UDP 5353 |
| network-policy-conformance-hufflepuff/cedric-diggory[StatefulSet] | network-policy-conformance-ravenclaw/luna-lovegood[StatefulSet] | All Connections |
| network-policy-conformance-hufflepuff/cedric-diggory[StatefulSet] | network-policy-conformance-slytherin/draco-malfoy[StatefulSet] | All Connections |
| network-policy-conformance-ravenclaw/luna-lovegood[StatefulSet] | 0.0.0.0-255.255.255.255[External] | All Connections |
| network-policy-conformance-ravenclaw/luna-lovegood[StatefulSet] | network-policy-conformance-gryffindor/harry-potter[StatefulSet] | All Connections |
| network-policy-conformance-ravenclaw/luna-lovegood[StatefulSet] | network-policy-conformance-hufflepuff/cedric-diggory[StatefulSet] | All Connections |
| network-policy-conformance-ravenclaw/luna-lovegood[StatefulSet] | network-policy-conformance-slytherin/draco-malfoy[StatefulSet] | All Connections |
| network-policy-conformance-slytherin/draco-malfoy[StatefulSet] | 0.0.0.0-255.255.255.255[External] | All Connections |
| network-policy-conformance-slytherin/draco-malfoy[StatefulSet] | network-policy-conformance-gryffindor/harry-potter[StatefulSet] | SCTP 1-9002,9004-65535,TCP 1-79,81-65535,UDP 1-52,54-65535 |
| network-policy-conformance-slytherin/draco-malfoy[StatefulSet] | network-policy-conformance-hufflepuff/cedric-diggory[StatefulSet] | All Connections |
| network-policy-conformance-slytherin/draco-malfoy[StatefulSet] | network-policy-conformance-ravenclaw/luna-lovegood[StatefulSet] | All Connections |
