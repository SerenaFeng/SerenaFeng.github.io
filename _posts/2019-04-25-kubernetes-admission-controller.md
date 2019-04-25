---
layout: post
title: "Kubernetes Admission Controller Profile"
subtitle: 'How Admission Controller works in Kubernetes'
author: 'serena'
head-style: text
tags: 
  - Kubernetes
  - admission controller
  - MutatingAdmissionWebhook
  - client-go
  - apimachinary
---

summary: in this article, we will inspect how Kubernetes handle admission controller events, and
         take the istio-sidecar-injector MutatingAdmissionWebhook as an example, we will explain
         how admission controller is implemented with the help of client-go and apimachinay.
