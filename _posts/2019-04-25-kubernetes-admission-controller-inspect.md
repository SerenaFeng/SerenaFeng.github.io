---
layout: post
title: "Kubernetes Admission Controller Inspect"
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

summary: in this article, we will inspect how admission controller events are handled by Kubernetes,
         and take the istio-sidecar-injector MutatingAdmissionWebhook as an example, we will explain
         how admission controller is implemented with the help of client-go and apimachinay.
