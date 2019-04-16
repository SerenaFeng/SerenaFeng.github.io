---
layout: post
title: "Istio sidecar injector"
subtitle: 'How to inject sidecar containers in Istio'
author: 'serena'
head-style: text
tags: 
  - Istio
  - service mesh
  - sidecar injector
---

update: The journey of Istio begins

---

To be a Istio mesh pod, the sidecar containers must be injected in every pod.
This is done automatically or manually.

# Sidecar containers

During the injecting, two containers will be injected to the pod, istio-init and istio-proxy:

`istio-init`
It is an [init container](<https://kubernetes.io/docs/concepts/workloads/pods/init-containers/>), 
used to setup the `iptables` rules, so that inbound and outbound traffic will to through the 
sidecar proxy.

`istio-proxy`
The actual sidecar proxy, route all the traffic in/out the pod (based on Envoy).

# Sidecar injection

In simple terms, sidecar injection is adding the configuration of the aforementioned containers to
the pod template. Both manual as well as automatic injection leverage the istio-sidecar-injector
configmap and the mesh's istio configmap to render the configuration.

Firstly let's take a look at the istio-sidecar-injector configmap, to get an idea of what actually is
going on.

```
$ kubectl -n istio-system get configmap istio-sidecar-injector -o=jsonpath='{.data.config}'

policy: enabled
template: |-
  initContainers:
  - name: istio-init
    image: docker.io/istio/proxy_init:1.0.2
    args:
    - "-p"
    - [[ .MeshConfig.ProxyListenPort ]]
    - "-u"
    - 1337
    .....
    imagePullPolicy: IfNotPresent
    securityContext:
      capabilities:
        add:
        - NET_ADMIN
    restartPolicy: Always

  containers:
  - name: istio-proxy
    image: [[ annotation .ObjectMeta `sidecar.istio.io/proxyImage`  "gcr.io/istio-release/proxyv2:release-1.1-latest-daily"  ]]
    ports:
    - containerPort: 15090
      protocol: TCP
      name: http-envoy-prom
    args:
    - proxy
    - sidecar
    .....
    env:
    .....
    - name: ISTIO_META_INTERCEPTION_MODE
      value: [[ or (index .ObjectMeta.Annotations "sidecar.istio.io/interceptionMode") .ProxyConfig.InterceptionMode.String ]]
    imagePullPolicy: IfNotPresent
    securityContext:
      readOnlyRootFilesystem: true
      [[ if eq (or (index .ObjectMeta.Annotations "sidecar.istio.io/interceptionMode") .ProxyConfig.InterceptionMode.String) "TPROXY" -]]
      capabilities:
        add:
        - NET_ADMIN
    restartPolicy: Always
    .....
```

As you can see, the configmap contains the configuration for both the istio-init container and the istio-proxy container.

Then, let's look at the istio configmap.

```
$ kubectl -n istio-system describe configmap istio

# Set the following variable to true to disable policy checks by the Mixer.
# Note that metrics will still be reported to the Mixer.
disablePolicyChecks: true

# Set enableTracing to false to disable request tracing.
enableTracing: true
......
defaultConfig:
  #
  # TCP connection timeout between Envoy & the application, and between Envoys.
  connectTimeout: 10s
  #
  ### ADVANCED SETTINGS #############
  # Where should envoy's configuration be stored in the istio-proxy container
  configPath: "/etc/istio/proxy"
  binaryPath: "/usr/local/bin/envoy"
  ......
meshNetworks:
----
networks: {}
```

As seen above, it defines [mesh-wide variables](<https://istio.io/docs/reference/config/istio.mesh.v1alpha1/>) 
shared by all Envoy instances.

## Manually

The manual way leverage the istioctl CLI tool to modify the pod template spec. You can inject the
the sidecar either using the in-cluster configuration:

```bash
$ istioctl kube-inject -f example.yaml --output example-injected.yaml
```

or using local copy of the configurations

```bash
$ istioctl kube-inject -f example.yaml \
                       --injectConfigFile istio-sidecar-injector-configmap.yaml \
                       --meshConfigFile istio-configmap.yaml \
                       --output example-injected.yaml
```

Write a new istio-sidecar-injector or istio configmap is a heavy and tedious work, the recommended
way is download the existed ones and modify:

```bash
$ kubectl -n istio-system get configmap istio-sidecar-injector -o=jsonpath='{.data.config}' > inject-config.yaml
$ kubectl -n istio-system get configmap istio -o=jsonpath='{.data.mesh}' > mesh-config.yaml
```

## Automatically

Most of the times, you don't want to manually inject the sidecar every time deploying the pod, but 
would prefer Istio doing that for you automatically, which is also the recommended approach. With 
the help of [MutatingAdmissionWebhook](<https://kubernetes.io/docs/admin/admission-controllers/>), 
Istio fulfill the requirements. 

And unlike the manual way, automatic sidecar injection happens when the pods are created, so nothing 
change will occur in the deployment configuration. To see the istio-init and istio-proxy you need to
use `kubectl describe`.

There are several configurations which control the automatic injection. 

- `namespaceSelector` configured in MutatingAdmissionWebhook
- `policy` configured in istio-sidecar-injector configmap
- `neverInjectSelector` configured in istio-sidecar-injector configmap
- `alwaysInjectSelector` configured in istio-sidecar-injector configmap
- `sidecar.istio.io/inject: true/false` in Pod annotation

### namespaceSelector

`namespaceSelector` is configured in istio-sidecar-injector MutatingWebhookConfiguration,
used to determine how the namespace is selected for auto injection. Let's look at it below: 

```bash
apiVersion: admissionregistration.k8s.io/v1beta1
kind: MutatingWebhookConfiguration
metadata:
  labels:
    app: sidecarInjectorWebhook
    chart: sidecarInjectorWebhook
    heritage: Tiller
    release: istio
  name: istio-sidecar-injector
  ......
webhooks:
- clientConfig:
    service:
      name: istio-sidecar-injector
      namespace: istio-system
      path: /inject
  failurePolicy: Fail
  name: sidecar-injector.istio.io
  namespaceSelector:
    matchLabels:
      istio-injection: enabled
  rules:
  - apiGroups:
    - ""
    apiVersions:
    - v1
    operations:
    - CREATE
    resources:
    - pods
  sideEffects: Unknown
```

With the above `namespaceSelector` configuration, if a namespace is labeled as
"istio-injection: enabled", the auto injection of the namespace is enabled, which means the pod
created under it will *possibly* get sidecar injected, here we use *possibly* because it may not be
injected due to the other factors, which we will introduce later. But if a namespace is not labeled as
"istio-injection: enabled", the pod created under it will definitely not get auto injected.

On the contrary, The `namespaceSelector` configuration shown below will allow all the namespaces
except `istio-system` to enable auto injection, unless it is labeled as "istio-injection: disabled". 

```yaml
......
webhooks:
- clientConfig:
    service:
      name: istio-sidecar-injector
      namespace: istio-system
      path: /inject
   ......
  namespaceSelector:
    matchExpressions:
    - key: name
      operator: NotIn
      values:
      - istio-system
    - key: istio-injection
      operator: NotIn
      values:
      - disabled
......
```

To change how namespaces are selected for the injection, you can edit `namespaceSelector` in 
`MutatingWebhookConfiguration` using the following mentioned method, and after modify it, you need
to restart the sidecar injector pod. 

```bash
$ kubectl edit mutatingwebhookconfiguration istio-sidecar-injector
```

To label the namespace, use 'kubectl label namespace' CLI command like below:

```bash
$ kubectl label namespace default istio-injection=enabled
```

### sidecar.istio.io/inject

`sidecar.istio.io/inject` is a kind of pod annotation, when the value if it is 'true', the pod will
be injected, or else, the pod will not be injected.

The following example uses the sidecar.istio.io/inject annotation to disable sidecar injection.

```yaml
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: example
spec:
  template:
    metadata:
      annotations:
        sidecar.istio.io/inject: "false"
  ......
```

### policy 

`policy` is configured in istio-sidecar-injector configmap, it is the default injection policy. It
is also a gate to determines whether the newly created pod will be automatically injected.

- disabled: The sidecar injector will not inject the sidecar into pods by default. But adding
  "sidecar.istio.io/inject: true" annotation to the pod template spec will override the default
  and enable injection.

- enabled: the sidecar injector will inject the sidecar into pods by default, except the pod's
  annotation clearly indicate not to inject by adding "sidecar.istio.io/inject: false"

### neverInjectSelector & alwaysInjectSelector

These are two determinations based on pod's label selector, configured in istio-sidecar-injector
configmap 

There are cases where users do not have control of the pod creation, when they are created by 
someone else. Therefore they are unable to add the annotation sidecar.istio.io/inject in the pod.
For such cases you can instruct Istio to not inject the sidecar on those pods, based on labels that
are present in those pods and `neverInjectSelector` configuration. While you can also instruct Istio
to auto inject the sidecar on those pod, based on labels and `alwaysInjectSelector` configuration.

Both `neverInjectSelector` and `alwaysInjectSelector` are array of
[Kubernetes label selectors](<https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#resources-that-support-set-based-requirements>).
They are `OR'd`, stopping at the first match. for examples:

istio-sidecar-injector configmap configures:

```yaml
    neverInjectSelector:
      - matchLabels:
          sidecar/label: notinject
      - matchExpressions:
        - {key: sidecar/notinject, operator: Exists}
    alwaysInjectSelector:
      - matchLabels:
          sidecar/label: inject
      - matchExpressions:
        - {key: sidecar/inject, operator: Exists}
```

When "sidecar/label: notinject" or "sidecar/notinject: <anyvalue>" is added in the pod's labels,
the auto inject will be disabled:

```yaml
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: example-v1
spec:
  replicas: 1
  template:
    metadata:
      labels:
        app: example
        version: v1
        sidecar/label: notinject
  ......
```

Whilst, when "sidecar/lable: inject" or "sidecar/inject: <anyvalue>" is added in the pod's labels,
the auto inject will be enabled:

```yaml
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: example-v1
spec:
  replicas: 1
  template:
    metadata:
      labels:
        app: example
        version: v1
        sidecar/inject: on
  ......
```

Note that `neverInjectSelector` has higher precedence than `alwaysInjectSelector`, which means if
the pod's labels match `neverInjectSelector` condition, the auto inject is rejected, no matter
whether or not `alwaysInjectSelector` matches. For example, with the following configuration, the
auto inject is disabled

```yaml
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: example-v1
spec:
  replicas: 1
  template:
    metadata:
      labels:
        app: example
        version: v1
        sidecar/label: notinject
        sidecar/inject: on
  ......
```

We have done experiments to test the effects of the mentioned control factors, see the table below.

| namespace | policy    | neverInjectSelector | alwaysInjectSelector | sidecar.istio.io/inject | Injected |
|-----------|-----------|---------------------|----------------------|-------------------------|----------|
|  true     |  enabled  |  match              |  match               | true                    |  yes     |
|  true     |  enabled  |  match              |  not-match           | true                    |  yes     |
|  true     |  enabled  |  not-match          |  match               | true                    |  yes     |
|  true     |  enabled  |  not-match          |  not-match           | true                    |  yes     |
|  true     |  enabled  |  match              |  match               | false                   |  no      |
|  true     |  enabled  |  match              |  not-match           | false                   |  no      |
|  true     |  enabled  |  not-match          |  match               | false                   |  no      |
|  true     |  enabled  |  not-match          |  not-match           | false                   |  no      |
|  true     |  enabled  |  match              |  match               |   -                     |  no      |
|  true     |  enabled  |  match              |  not-match           |   -                     |  no      |
|  true     |  enabled  |  not-match          |  match               |   -                     |  yes     |
|  true     |  enabled  |  not-match          |  not-match           |   -                     |  yes     |
|  true     |  disabled |  match              |  match               | true                    |  yes     |
|  true     |  disabled |  match              |  not-match           | true                    |  yes     |
|  true     |  disabled |  not-match          |  match               | true                    |  yes     |
|  true     |  disabled |  not-match          |  not-match           | true                    |  yes     |
|  true     |  disabled |  match              |  match               | false                   |  no      |
|  true     |  disabled |  match              |  not-match           | false                   |  no      |
|  true     |  disabled |  not-match          |  match               | false                   |  no      |
|  true     |  disabled |  not-match          |  not-match           | false                   |  no      |
|  true     |  disabled |  match              |  match               |   -                     |  no      |
|  true     |  disabled |  match              |  not-match           |   -                     |  no      |
|  true     |  disabled |  not-match          |  match               |   -                     |  yes     |
|  true     |  disabled |  not-match          |  not-match           |   -                     |  no      |


Note that for the cases which based on namespace not satisfied are not listed,
because they are doomed to be not injected, reference [namespaceSelector](#namespaceselector).

According to the table, we can come to the conclusion that `sidecar.istio.io/inject` annotation
in the pods have the highest precedence, `neverInjectSelector` follows, after that is the
`alwaysInjectSelector`,  the aftermost is `policy`:

    `sidecar.istio.io/inject → NeverInjectSelector → AlwaysInjectSelector → policy`

1. If `sidecar.istio.io/inject: true` is added in the pod's annotation, the pod will be injected.
2. If `sidecar.istio.io/inject: false` is added in the pod's annotation, the pod will not be injected.
3. Under the condition that `sidecar.istio.io/inject` annotation is not added, if the
   `neverInjectSelector` matches, the pod will not be injected. 
4. Under the condition that `sidecar.istio.io/inject` annotation is not added, if the
   `alwaysInjectSelector` matches and `neverInjectSelector` not match, the pod will be injected. 
5. Under the condition that `sidecar.istio.io/inject` annotation is not added, neither
   `neverInjectSelector` nor `alwaysInjectSelector` matches, if the policy is `enabled`, 
   the pod will be injected
6. Under the condition that `sidecar.istio.io/inject` annotation is not added, neither
   `neverInjectSelector` nor `alwaysInjectSelector` matches, if the policy is `disabled`, 
   the pod will not be injected
