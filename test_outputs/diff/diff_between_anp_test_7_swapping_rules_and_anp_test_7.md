| diff-type | source | destination | ref1 | ref2 | workloads-diff-info |
|-----------|--------|-------------|------|------|---------------------|
| changed | network-policy-conformance-slytherin/draco-malfoy[StatefulSet] | network-policy-conformance-gryffindor/harry-potter[StatefulSet] | All but: TCP 80 | All Connections |  |
| removed | network-policy-conformance-hufflepuff/cedric-diggory[StatefulSet] | network-policy-conformance-gryffindor/harry-potter[StatefulSet] | TCP 80 | No Connections |  |