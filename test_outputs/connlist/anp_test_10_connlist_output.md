| src | dst | conn |
|-----|-----|------|
| 0.0.0.0-255.255.255.255[External] | network-policy-conformance-gryffindor/harry-potter[StatefulSet] | All Connections |
| 0.0.0.0-255.255.255.255[External] | network-policy-conformance-hufflepuff/cedric-diggory[StatefulSet] | All Connections |
| 0.0.0.0-255.255.255.255[External] | network-policy-conformance-ravenclaw/luna-lovegood[StatefulSet] | All Connections |
| 0.0.0.0-255.255.255.255[External] | network-policy-conformance-slytherin/draco-malfoy[StatefulSet] | All Connections |
| network-policy-conformance-gryffindor/harry-potter[StatefulSet] | 0.0.0.0-255.255.255.255[External] | All Connections |
| network-policy-conformance-gryffindor/harry-potter[StatefulSet] | network-policy-conformance-hufflepuff/cedric-diggory[StatefulSet] | All Connections |
| network-policy-conformance-gryffindor/harry-potter[StatefulSet] | network-policy-conformance-ravenclaw/luna-lovegood[StatefulSet] | All Connections |
| network-policy-conformance-gryffindor/harry-potter[StatefulSet] | network-policy-conformance-slytherin/draco-malfoy[StatefulSet] | All Connections |
| network-policy-conformance-hufflepuff/cedric-diggory[StatefulSet] | 0.0.0.0-255.255.255.255[External] | All Connections |
| network-policy-conformance-hufflepuff/cedric-diggory[StatefulSet] | network-policy-conformance-gryffindor/harry-potter[StatefulSet] | UDP 53 |
| network-policy-conformance-hufflepuff/cedric-diggory[StatefulSet] | network-policy-conformance-ravenclaw/luna-lovegood[StatefulSet] | All Connections |
| network-policy-conformance-hufflepuff/cedric-diggory[StatefulSet] | network-policy-conformance-slytherin/draco-malfoy[StatefulSet] | SCTP 1-65535,TCP 1-65535,UDP 1-5352,5354-65535 |
| network-policy-conformance-ravenclaw/luna-lovegood[StatefulSet] | 0.0.0.0-255.255.255.255[External] | All Connections |
| network-policy-conformance-ravenclaw/luna-lovegood[StatefulSet] | network-policy-conformance-gryffindor/harry-potter[StatefulSet] | All Connections |
| network-policy-conformance-ravenclaw/luna-lovegood[StatefulSet] | network-policy-conformance-hufflepuff/cedric-diggory[StatefulSet] | All Connections |
| network-policy-conformance-ravenclaw/luna-lovegood[StatefulSet] | network-policy-conformance-slytherin/draco-malfoy[StatefulSet] | All Connections |
| network-policy-conformance-slytherin/draco-malfoy[StatefulSet] | 0.0.0.0-255.255.255.255[External] | All Connections |
| network-policy-conformance-slytherin/draco-malfoy[StatefulSet] | network-policy-conformance-gryffindor/harry-potter[StatefulSet] | All Connections |
| network-policy-conformance-slytherin/draco-malfoy[StatefulSet] | network-policy-conformance-hufflepuff/cedric-diggory[StatefulSet] | All Connections |
| network-policy-conformance-slytherin/draco-malfoy[StatefulSet] | network-policy-conformance-ravenclaw/luna-lovegood[StatefulSet] | All Connections |
