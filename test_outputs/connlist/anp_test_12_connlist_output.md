| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255 | network-policy-conformance-gryffindor/harry-potter[StatefulSet] | All Connections |
| 0.0.0.0-255.255.255.255 | network-policy-conformance-hufflepuff/cedric-diggory[StatefulSet] | All Connections |
| 0.0.0.0-255.255.255.255 | network-policy-conformance-ravenclaw/luna-lovegood[StatefulSet] | All Connections |
| 0.0.0.0-255.255.255.255 | network-policy-conformance-slytherin/draco-malfoy[StatefulSet] | All Connections |
| network-policy-conformance-gryffindor/harry-potter[StatefulSet] | 0.0.0.0-255.255.255.255 | All Connections |
| network-policy-conformance-gryffindor/harry-potter[StatefulSet] | network-policy-conformance-hufflepuff/cedric-diggory[StatefulSet] | All Connections |
| network-policy-conformance-gryffindor/harry-potter[StatefulSet] | network-policy-conformance-ravenclaw/luna-lovegood[StatefulSet] | All Connections |
| network-policy-conformance-gryffindor/harry-potter[StatefulSet] | network-policy-conformance-slytherin/draco-malfoy[StatefulSet] | All Connections |
| network-policy-conformance-hufflepuff/cedric-diggory[StatefulSet] | 0.0.0.0-255.255.255.255 | All Connections |
| network-policy-conformance-hufflepuff/cedric-diggory[StatefulSet] | network-policy-conformance-gryffindor/harry-potter[StatefulSet] | All Connections |
| network-policy-conformance-hufflepuff/cedric-diggory[StatefulSet] | network-policy-conformance-ravenclaw/luna-lovegood[StatefulSet] | All Connections |
| network-policy-conformance-hufflepuff/cedric-diggory[StatefulSet] | network-policy-conformance-slytherin/draco-malfoy[StatefulSet] | All Connections |
| network-policy-conformance-ravenclaw/luna-lovegood[StatefulSet] | 0.0.0.0-255.255.255.255 | All Connections |
| network-policy-conformance-ravenclaw/luna-lovegood[StatefulSet] | network-policy-conformance-gryffindor/harry-potter[StatefulSet] | All Connections |
| network-policy-conformance-ravenclaw/luna-lovegood[StatefulSet] | network-policy-conformance-hufflepuff/cedric-diggory[StatefulSet] | SCTP 9003 |
| network-policy-conformance-ravenclaw/luna-lovegood[StatefulSet] | network-policy-conformance-slytherin/draco-malfoy[StatefulSet] | SCTP 1-9002,9004-65535,TCP 1-65535,UDP 1-65535 |
| network-policy-conformance-slytherin/draco-malfoy[StatefulSet] | 0.0.0.0-255.255.255.255 | All Connections |
| network-policy-conformance-slytherin/draco-malfoy[StatefulSet] | network-policy-conformance-gryffindor/harry-potter[StatefulSet] | All Connections |
| network-policy-conformance-slytherin/draco-malfoy[StatefulSet] | network-policy-conformance-hufflepuff/cedric-diggory[StatefulSet] | All Connections |
| network-policy-conformance-slytherin/draco-malfoy[StatefulSet] | network-policy-conformance-ravenclaw/luna-lovegood[StatefulSet] | All Connections |