| diff-type | source | destination | ref1 | ref2 | workloads-diff-info |
|-----------|--------|-------------|------|------|---------------------|
| changed | network-policy-conformance-gryffindor/harry-potter[StatefulSet] | network-policy-conformance-slytherin/draco-malfoy[StatefulSet] | SCTP 1-9002,9004-65535,TCP 1-79,81-65535,UDP 1-52,54-65535 | All Connections |  |
| changed | network-policy-conformance-slytherin/draco-malfoy[StatefulSet] | network-policy-conformance-gryffindor/harry-potter[StatefulSet] | SCTP 1-9002,9004-65535,TCP 1-79,81-65535,UDP 1-52,54-65535 | All Connections |  |
| removed | network-policy-conformance-gryffindor/harry-potter[StatefulSet] | network-policy-conformance-ravenclaw/luna-lovegood[StatefulSet] | All Connections | No Connections |  |
| removed | network-policy-conformance-ravenclaw/luna-lovegood[StatefulSet] | network-policy-conformance-gryffindor/harry-potter[StatefulSet] | All Connections | No Connections |  |