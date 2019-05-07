---
layout: post
title: Kubernetes Admission Controller Inspect
subtitle: How Admission Controller works in Kubernetes
author: serena
head-style: text
tags: 
  - Kubernetes
  - admission controller
  - MutatingAdmissionWebhook
  - client-go
  - apimachinary
---

summary: in this article, we will inspect how admission webhook events are handled by Kubernetes,
         and explain how admission webhook is developed with the help of client-go and apimachinay.

# Admission Controller Overview

To start, let's take a look at the official definition of admission controllers.

```text
An admission controller is a piece of code that intercepts requests to the Kubernetes API server
prior to persistence of the object, but after the request is authenticated and authorized.

......

standard, plugin-style admission controllers are not flexible enough for all user cases, due to the
following:

* They need to be compiled into kube-apiserver
* They are only configurable when the apiserver starts up

Admission Webhooks addresses these limitations. It allows admission controllers to be developed
out-of-tree and configured at runtime.
```

We can see that there are two kinds of admission controllers, static style and dynamic style.

- Static admission controller work in plugin mode, must be compiled into kube-apiserver and can only
  be enabled when kube-apiserver starts up. 
- Dynamic admission controller. Basically there are two kinds, 
  [MutatingAdmissionWebhook](<https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#mutatingadmissionwebhook>)
  and
  [ValidatingAdmissionWebhook](<https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#validatingadmissionwebhook>),
  they are configured in the API.

# What is an admission webhook?

```text
Admission webhooks are HTTP callbacks that receive admission requests and do something with them.
You can define two types of admission webhooks, validating admission Webhook and mutating admission
webhook. With validating admission Webhooks, you may reject requests to enforce custom admission
policies. With mutating admission Webhooks, you may change requests to enforce custom defaults.
```

There are two admission webhooks, MutatingAdmissionWebhook and ValidatingAdmissionWebhook, the
difference between them is pretty self-explanatory: validating may reject a request, but they may
not modify the object they are receiving in the admission request. While mutating may modify objects
by creating a patch that sent back in the admission response. If any of the webhook controller
rejects the request, an error will be returned to the end-user.

After configuring MutatingAdmissionWebhook and ValidatingAdmissionWebhook, the API request lifecycle
of Kubernetes is as below:

![](/img/posts/kubernetes-api-lifecycle.png)

