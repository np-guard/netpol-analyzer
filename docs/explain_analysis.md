# Explain analysis - enhance `list` connectivity analysis

## Motivation

`list` without `--exposure`, produces a report of permitted connectivity between pairs of nodes, without an explanation what resources contributed to this connectivity being allowed.\
Likewise, it does not detail neither explain all denied connectivity.

The goal of explainability analysis is to provide this additional information, specifying the resources (such as network policies, admin network policies, routes and more) that contributed to allowing or denying a connectivity between any pair of nodes.
This report can help testing whether the configured resources induce connectivity as expected, and give hints to where the resources may be changed to 
 achieve the desired result.

The explainability analysis is currently supported for txt output format of the `list` command. 
To run explainability analysis, just run the `list` command with the additional `--explain` flag. 

The section below details a comprehensive example of input manifests for workloads and network policies, and shows the output result of explainability analysis.


## Example

### Input Manifests:
`Namespaces and Pods`:
```
---
apiVersion: v1
kind: Namespace
metadata:
  name: foo
  labels:
    security: internal
    kubernetes.io/metadata.name: foo
    
---
apiVersion: v1
kind: Namespace
metadata:
  name: bar
  labels:
    security: internal
    kubernetes.io/metadata.name: bar

---
apiVersion: v1
kind: Namespace
metadata:
  name: baz
  labels:    
    kubernetes.io/metadata.name: baz

---
apiVersion: v1
kind: Namespace
metadata:
  name: monitoring
  labels:
    kubernetes.io/metadata.name: monitoring        

---
apiVersion: v1
kind: Pod
metadata:
  namespace: foo
  name: myfoo
  labels:
    security: internal
spec:
  containers:
    - name: myfirstcontainer
      image: fooimage

---
apiVersion: v1
kind: Pod
metadata:
  namespace: bar
  name: mybar
  labels:
    security: internal
spec:
  containers:
    - name: myfirstcontainer
      image: barimage

---
apiVersion: v1
kind: Pod
metadata:
  namespace: baz
  name: mybaz
  labels:
    security: none
spec:
  containers:
    - name: myfirstcontainer
      image: bazimage

---
apiVersion: v1
kind: Pod
metadata:
  namespace: monitoring
  name: mymonitoring
  labels:
    security: monitoring
spec:
  containers:
    - name: myfirstcontainer
      image: monitoringimage

```

`NetworkPolicy`:
```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-monitoring
  namespace: foo
spec:
  podSelector:
  policyTypes:
    - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: monitoring
```

`BaselineAdminNetworkPolicy`:
```
apiVersion: policy.networking.k8s.io/v1alpha1
kind: BaselineAdminNetworkPolicy
metadata:
  name: default
spec:
  subject:
    namespaces:
      matchLabels:
        security: internal
  ingress:
  - name: "deny-ingress-from-all-namespaces-on-TCP1-9000"
    action: "Deny"
    from:
    - namespaces:
          matchLabels:
            kubernetes.io/metadata.name: monitoring
    ports:
      - portRange:
          protocol: TCP
          start: 1
          end: 9000
```

`AdminNetworkPolicies`:
```
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: allow-monitoring
spec:
  priority: 9
  subject:
    namespaces: {}
  ingress:
  - name: "allow-ingress-from-monitoring-on-TCP1234"
    action: "Allow"
    from:
    - namespaces:
          matchLabels:
            kubernetes.io/metadata.name: monitoring
    ports:
      - portNumber:
          protocol: TCP
          port: 1234
            
---
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: pass-monitoring
spec:
  priority: 7
  subject:
    namespaces:
      matchLabels:
        security: internal
  ingress:
  - name: "pass-ingress-from-monitoring-on-TCP8080"
    action: "Pass"
    from:
    - namespaces:
          matchLabels:
            kubernetes.io/metadata.name: monitoring
    ports:
      - portNumber:
          protocol: TCP
          port: 8080

```
#### Textual Result:
```
----------------------------------------------------------------------------------------------------------------------------------------------------------------
CONNECTIONS BETWEEN 0.0.0.0-255.255.255.255 => foo/myfoo[Pod]:

No Connections due to the following policies//rules:
	EGRESS DIRECTION (ALLOWED) due to the system default (Allow all)
	INGRESS DIRECTION (DENIED)
		1) [NP] foo/allow-monitoring//Ingress (captured but not selected by any Ingress rule)

----------------------------------------------------------------------------------------------------------------------------------------------------------------
CONNECTIONS BETWEEN bar/mybar[Pod] => foo/myfoo[Pod]:

No Connections due to the following policies//rules:
	EGRESS DIRECTION (ALLOWED) due to the system default (Allow all)
	INGRESS DIRECTION (DENIED)
		1) [NP] foo/allow-monitoring//Ingress (captured but not selected by any Ingress rule)

----------------------------------------------------------------------------------------------------------------------------------------------------------------
CONNECTIONS BETWEEN baz/mybaz[Pod] => foo/myfoo[Pod]:

No Connections due to the following policies//rules:
	EGRESS DIRECTION (ALLOWED) due to the system default (Allow all)
	INGRESS DIRECTION (DENIED)
		1) [NP] foo/allow-monitoring//Ingress (captured but not selected by any Ingress rule)

----------------------------------------------------------------------------------------------------------------------------------------------------------------
CONNECTIONS BETWEEN monitoring/mymonitoring[Pod] => bar/mybar[Pod]:

ALLOWED TCP:[1234] due to the following policies//rules:
	EGRESS DIRECTION (ALLOWED) due to the system default (Allow all)
	INGRESS DIRECTION (ALLOWED)
		1) [ANP] allow-monitoring//Ingress rule allow-ingress-from-monitoring-on-TCP1234 (Allow)

ALLOWED TCP:[9001-65535] the system default (Allow all)

ALLOWED {SCTP,UDP}:[ALL PORTS] the system default (Allow all)

DENIED TCP:[1-1233,1235-8079,8081-9000] due to the following policies//rules:
	EGRESS DIRECTION (ALLOWED) due to the system default (Allow all)
	INGRESS DIRECTION (DENIED)
		1) [BANP] default//Ingress rule deny-ingress-from-all-namespaces-on-TCP1-9000 (Deny)

DENIED TCP:[8080] due to the following policies//rules:
	EGRESS DIRECTION (ALLOWED) due to the system default (Allow all)
	INGRESS DIRECTION (DENIED)
		1) [ANP] pass-monitoring//Ingress rule pass-ingress-from-monitoring-on-TCP8080 (Pass)
		2) [BANP] default//Ingress rule deny-ingress-from-all-namespaces-on-TCP1-9000 (Deny)

----------------------------------------------------------------------------------------------------------------------------------------------------------------
CONNECTIONS BETWEEN monitoring/mymonitoring[Pod] => baz/mybaz[Pod]:

ALLOWED TCP:[1-1233,1235-65535] the system default (Allow all)

ALLOWED TCP:[1234] due to the following policies//rules:
	EGRESS DIRECTION (ALLOWED) due to the system default (Allow all)
	INGRESS DIRECTION (ALLOWED)
		1) [ANP] allow-monitoring//Ingress rule allow-ingress-from-monitoring-on-TCP1234 (Allow)

ALLOWED {SCTP,UDP}:[ALL PORTS] the system default (Allow all)

----------------------------------------------------------------------------------------------------------------------------------------------------------------
CONNECTIONS BETWEEN monitoring/mymonitoring[Pod] => foo/myfoo[Pod]:

ALLOWED TCP:[1-1233,1235-8079,8081-65535] due to the following policies//rules:
	EGRESS DIRECTION (ALLOWED) due to the system default (Allow all)
	INGRESS DIRECTION (ALLOWED)
		1) [NP] foo/allow-monitoring//Ingress rule #1

ALLOWED TCP:[1234] due to the following policies//rules:
	EGRESS DIRECTION (ALLOWED) due to the system default (Allow all)
	INGRESS DIRECTION (ALLOWED)
		1) [ANP] allow-monitoring//Ingress rule allow-ingress-from-monitoring-on-TCP1234 (Allow)

ALLOWED TCP:[8080] due to the following policies//rules:
	EGRESS DIRECTION (ALLOWED) due to the system default (Allow all)
	INGRESS DIRECTION (ALLOWED)
		1) [ANP] pass-monitoring//Ingress rule pass-ingress-from-monitoring-on-TCP8080 (Pass)
		2) [NP] foo/allow-monitoring//Ingress rule #1

ALLOWED {SCTP,UDP}:[ALL PORTS] due to the following policies//rules:
	EGRESS DIRECTION (ALLOWED) due to the system default (Allow all)
	INGRESS DIRECTION (ALLOWED)
		1) [NP] foo/allow-monitoring//Ingress rule #1

----------------------------------------------------------------------------------------------------------------------------------------------------------------
The following nodes are connected due to the system default (Allow all):
0.0.0.0-255.255.255.255 => bar/mybar[Pod]
0.0.0.0-255.255.255.255 => baz/mybaz[Pod]
0.0.0.0-255.255.255.255 => monitoring/mymonitoring[Pod]
bar/mybar[Pod] => 0.0.0.0-255.255.255.255
bar/mybar[Pod] => baz/mybaz[Pod]
bar/mybar[Pod] => monitoring/mymonitoring[Pod]
baz/mybaz[Pod] => 0.0.0.0-255.255.255.255
baz/mybaz[Pod] => bar/mybar[Pod]
baz/mybaz[Pod] => monitoring/mymonitoring[Pod]
foo/myfoo[Pod] => 0.0.0.0-255.255.255.255
foo/myfoo[Pod] => bar/mybar[Pod]
foo/myfoo[Pod] => baz/mybaz[Pod]
foo/myfoo[Pod] => monitoring/mymonitoring[Pod]
monitoring/mymonitoring[Pod] => 0.0.0.0-255.255.255.255
```
