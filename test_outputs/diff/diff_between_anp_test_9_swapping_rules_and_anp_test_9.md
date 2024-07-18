| diff-type | source | destination | ref1 | ref2 | workloads-diff-info |
|-----------|--------|-------------|------|------|---------------------|
| changed | network-policy-conformance-gryffindor/harry-potter[StatefulSet] | network-policy-conformance-slytherin/draco-malfoy[StatefulSet] | All but: SCTP 9003,TCP 80,UDP 53 | All Connections |  |
| changed | network-policy-conformance-slytherin/draco-malfoy[StatefulSet] | network-policy-conformance-gryffindor/harry-potter[StatefulSet] | All but: SCTP 9003,TCP 80,UDP 53 | All Connections |  |
| removed | network-policy-conformance-gryffindor/harry-potter[StatefulSet] | network-policy-conformance-ravenclaw/luna-lovegood[StatefulSet] | All Connections | No Connections |  |
| removed | network-policy-conformance-ravenclaw/luna-lovegood[StatefulSet] | network-policy-conformance-gryffindor/harry-potter[StatefulSet] | All Connections | No Connections |  |