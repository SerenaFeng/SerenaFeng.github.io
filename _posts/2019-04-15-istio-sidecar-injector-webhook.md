---
layout: post
title: "istio-sidecar-injector source code analysis"
subtitle: 'How istio sidecar injector works'
author: 'serena'
head-style: text
tags: 
  - Istio
  - service mesh
  - sidecar injector
---

As mentioned in the [previous blog](<https://serenafeng.github.io/2019/04/10/istio-sidecar-injector/>),
Istio leverage the [MutatingAdmissionWebhook](<https://kubernetes.io/docs/admin/admission-controllers/>)
to implement automatic sidecar injection. In this article, we will introduce how the automatic
injection works through understanding the source code of istio-sidecar-injector webhook.

- entry file: istio/pilot/cmd/sidecar-injector/main.go
- Dockerfile: istio/pilot/docker/Dockerfile.sidecar_injector
- CLI command: /usr/local/bin/sidecar-injector

## Parameters if CLI command

First of all, let's take a look at the startup parameters when starting the sidecar-injector
progress in container sidecar-injector-webhook.

```yaml
$ k istio g pod -l app=sidecarInjectorWebhook -o yaml
apiVersion: v1
items:
- apiVersion: v1
  kind: Pod
  spec:
    containers:
    - args:
      - --caCertFile=/etc/istio/certs/root-cert.pem
      - --tlsCertFile=/etc/istio/certs/cert-chain.pem
      - --tlsKeyFile=/etc/istio/certs/key.pem
      - --injectConfig=/etc/istio/inject/config
      - --meshConfig=/etc/istio/config/mesh
      - --healthCheckInterval=2s
      - --healthCheckFile=/health
      image: gcr.io/istio-release/sidecar_injector:master-latest-daily
      volumeMounts:
      - mountPath: /etc/istio/config
        name: config-volume
        readOnly: true
      - mountPath: /etc/istio/certs
        name: certs
        readOnly: true
      - mountPath: /etc/istio/inject
        name: inject-config
        readOnly: true
      - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
        name: istio-sidecar-injector-service-account-token-5qnfc
        readOnly: true
    volumes:
    - configMap:
        defaultMode: 420
        name: istio
      name: config-volume
    - name: certs
      secret:
        defaultMode: 420
        secretName: istio.istio-sidecar-injector-service-account
    - configMap:
        defaultMode: 420
        items:
        - key: config
          path: config
        name: istio-sidecar-injector
      name: inject-config
    - name: istio-sidecar-injector-service-account-token-5qnfc
      secret:
        defaultMode: 420
        secretName: istio-sidecar-injector-service-account-token-5qnfc
```

The two major configs are injectConfig and meshConfig, which are from configmaps of 
istio-sidecar-injector and istio via
[projected volume mount](<https://kubernetes.io/docs/concepts/storage/volumes/#projected>).

