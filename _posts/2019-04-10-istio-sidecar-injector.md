---
layout: post
title: "Istio sidecar injector"
subtitle: 'How to inject sidecar containers in Istio'
author: 'serena'
head-style: text
tags: 
  - Istio
  - service mesh
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

## Automatically

Most of the times, you don't want to manually inject the sidecar every time deploying the pod, but 
would prefer Istio doing that for you automatically, which is also the recommended approach. With 
the help of [MutatingAdmissionWebhook](<https://kubernetes.io/docs/admin/admission-controllers/>), 
Istio fulfill the requirements. Let's take a look at the istio-sidecar-injector mutating webhook 
configuration.

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

`namespaceSelector` label is used to match the namespace for sidecar injection with the label
`istio-injection: enabled`. To change how namespaces are selected for the injection, you can edit
`MutatingWebhookConfiguration` using `kubectl edit mutatingwebhookconfiguration istio-sidecar-injector`,
after that restart the sidecar injector pod. 

Unlike the manual way, automatic sidecar injection happens when the pods are created, so nothing 
change will occur in the deployment configuration. To see the istio-init and istio-proxy you need to
use `kubectl describe`.

There are several ways to control the automatic injection. Let's summarize below:

### policy field in istio-sidecar-injector configmap 

This field is used to determine whether or not inject the sidecar into pods by default. 