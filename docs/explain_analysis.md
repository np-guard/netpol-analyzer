# Explain analysis - enhance `list` connectivity analysis

## Motivation

`list` without `--explain`, produces a report of permitted connectivity between pairs of nodes, without an explanation what resources contributed to this connectivity being allowed.\
Likewise, it does not detail neither explain all denied connectivity.

The goal of `--explain` analysis is to provide this additional information, specifying the resources (such as network policies, admin network policies, routes and more) that contributed to allowing or denying a connectivity between any pair of workloads.
This report can help testing whether the configured resources induce connectivity as expected, and give hints to where the resources may be changed to 
 achieve the desired result.

The `--explain` analysis is currently supported for `txt` output format of the `list` command. 
To run explainability analysis, just run the `list` command with the additional `--explain` flag. 

The section below details a comprehensive example of input manifests for workloads and network policies, and shows the output result of explainability analysis.


## Example

### Input Manifests:

See source file [here](../tests/anp_banp_blog_demo).

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
  - name: "deny-ingress-from-all-namespaces"
    action: "Deny"
    from:
    - namespaces: {}
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
  - name: "allow-ingress-from-monitoring"
    action: "Allow"
    from:
    - namespaces:
          matchLabels:
            kubernetes.io/metadata.name: monitoring


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
  - name: "pass-ingress-from-monitoring"
    action: "Pass"
    from:
    - namespaces:
          matchLabels:
            kubernetes.io/metadata.name: monitoring

```
#### Textual Result:


Running  as `netpol-analyzer list --dirpath tests/anp_banp_blog_demo/ --explain`

```
##########################################
# Specific connections and their reasons #
##########################################
----------------------------------------------------------------------------------------------------------------------------------------------------------------
Connections between 0.0.0.0-255.255.255.255 => foo/myfoo[Pod]:

Denied connections:
        Denied TCP, UDP, SCTP due to the following policies and rules:
                Egress (Allowed) due to the system default (Allow all)
                Ingress (Denied)
                        NetworkPolicy 'foo/allow-monitoring' selects foo/myfoo[Pod], but 0.0.0.0-255.255.255.255 is not allowed by any Ingress rule

----------------------------------------------------------------------------------------------------------------------------------------------------------------
Connections between bar/mybar[Pod] => foo/myfoo[Pod]:

Denied connections:
        Denied TCP, UDP, SCTP due to the following policies and rules:
                Egress (Allowed) due to the system default (Allow all)
                Ingress (Denied)
                        NetworkPolicy 'foo/allow-monitoring' selects foo/myfoo[Pod], but bar/mybar[Pod] is not allowed by any Ingress rule

----------------------------------------------------------------------------------------------------------------------------------------------------------------
Connections between baz/mybaz[Pod] => bar/mybar[Pod]:

Denied connections:
        Denied TCP, UDP, SCTP due to the following policies and rules:
                Egress (Allowed) due to the system default (Allow all)
                Ingress (Denied)
                        BaselineAdminNetworkPolicy 'default' denies connections by Ingress rule deny-ingress-from-all-namespaces

----------------------------------------------------------------------------------------------------------------------------------------------------------------
Connections between baz/mybaz[Pod] => foo/myfoo[Pod]:

Denied connections:
        Denied TCP, UDP, SCTP due to the following policies and rules:
                Egress (Allowed) due to the system default (Allow all)
                Ingress (Denied)
                        NetworkPolicy 'foo/allow-monitoring' selects foo/myfoo[Pod], but baz/mybaz[Pod] is not allowed by any Ingress rule

----------------------------------------------------------------------------------------------------------------------------------------------------------------
Connections between foo/myfoo[Pod] => bar/mybar[Pod]:

Denied connections:
        Denied TCP, UDP, SCTP due to the following policies and rules:
                Egress (Allowed) due to the system default (Allow all)
                Ingress (Denied)
                        BaselineAdminNetworkPolicy 'default' denies connections by Ingress rule deny-ingress-from-all-namespaces

----------------------------------------------------------------------------------------------------------------------------------------------------------------
Connections between monitoring/mymonitoring[Pod] => bar/mybar[Pod]:

Denied connections:
        Denied TCP, UDP, SCTP due to the following policies and rules:
                Egress (Allowed) due to the system default (Allow all)
                Ingress (Denied)
                        AdminNetworkPolicy 'pass-monitoring' passes connections by Ingress rule pass-ingress-from-monitoring
                        BaselineAdminNetworkPolicy 'default' denies connections by Ingress rule deny-ingress-from-all-namespaces

----------------------------------------------------------------------------------------------------------------------------------------------------------------
Connections between monitoring/mymonitoring[Pod] => baz/mybaz[Pod]:

Allowed connections:
        Allowed TCP, UDP, SCTP due to the following policies and rules:
                Egress (Allowed) due to the system default (Allow all)
                Ingress (Allowed)
                        AdminNetworkPolicy 'allow-monitoring' allows connections by Ingress rule allow-ingress-from-monitoring

----------------------------------------------------------------------------------------------------------------------------------------------------------------
Connections between monitoring/mymonitoring[Pod] => foo/myfoo[Pod]:

Allowed connections:
        Allowed TCP, UDP, SCTP due to the following policies and rules:
                Egress (Allowed) due to the system default (Allow all)
                Ingress (Allowed)
                        AdminNetworkPolicy 'pass-monitoring' passes connections by Ingress rule pass-ingress-from-monitoring
                        NetworkPolicy 'foo/allow-monitoring' allows connections by Ingress rule #1


#########################################################
# All Connections due to the system default (Allow all) #
#########################################################
0.0.0.0-255.255.255.255 => bar/mybar[Pod]
0.0.0.0-255.255.255.255 => baz/mybaz[Pod]
0.0.0.0-255.255.255.255 => monitoring/mymonitoring[Pod]
bar/mybar[Pod] => 0.0.0.0-255.255.255.255
bar/mybar[Pod] => baz/mybaz[Pod]
bar/mybar[Pod] => monitoring/mymonitoring[Pod]
baz/mybaz[Pod] => 0.0.0.0-255.255.255.255
baz/mybaz[Pod] => monitoring/mymonitoring[Pod]
foo/myfoo[Pod] => 0.0.0.0-255.255.255.255
foo/myfoo[Pod] => baz/mybaz[Pod]
foo/myfoo[Pod] => monitoring/mymonitoring[Pod]
monitoring/mymonitoring[Pod] => 0.0.0.0-255.255.255.255
```