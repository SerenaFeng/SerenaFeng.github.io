---
layout: post
title: Deep Dive kube-proxy with iptables mode
author: serena
head-style: text
tags: 
  - Kubernetes
  - kube-proxy
  - iptables
  - service
  - headless service
---

summary: in Kubernetes, a Service is an abstraction which defines a logical set 
         of Pods and a policy by which to access them, and kube-proxy which sits 
         on every node, is employed to maintain network rules for forwarding 
         connections for endpoints associated with services. In this post, we will 
         introduce when working in iptables mode, how kube-proxy handles the 
         forwarding of traffic.

# 3 modes

kube-proxy triggers the configure of routing rules by watching 
kube-apiserver for the addition and removal of Service and Endpoints objects,
currently, it supports three different operation modes:

## User space

In this mode, for each Service, it opens a port(randomly chosen) on the local node. 
Any connections to this “proxy port” are proxied to one of the Service’s backend 
Pods. It is not commonly used as it is slow and outdated.

## iptables

Built on Netfilter. For each Service, it installs iptables rules, which capture 
traffic to the Service’s clusterIP and port, and redirect that traffic to one of 
the Service’s backend sets. For each Endpoint object, it installs iptables rules 
which select a backend Pod. It is the default mode for most platforms. 

## IPVS

This mode calls netlink interface to create IPVS rules accordingly and synchronizes 
IPVS rules with Kubernetes Services and Endpoints periodically. it requires the 
Linux kernel to have the IPVS modules loaded.

# externalTrafficPolicy

This configuration denotes if this Service desires to route external traffic to 
node-local or cluster-wide endpoints. There are two available options: 
Cluster(default) and Local

## Cluster

It is the default option, and has the following attributes:

- packets sent to the service with type=NodePort or type=LoadBalance are SNAT'd 
  by the node's IP.
- if external packet is routed to a node which has no pod retained, the proxy will
  forward it to a pod on another host. This may cause an extra hop, which is bad.
- kubernetes performs the balancing within the cluster, which means the number of
  pods is taken into account when do the balancing, so it has a good overall 
  load-spreading.

![](/img/posts/kube-proxy/externalTrafficPolicy-cluster.png)

## Local

- packets are not SNAT'd in any service type.
- when the packet comes to a no-pod-retained node, it gets dropped, which avoids
  the extra hop between nodes.
- kubernetes performs the balancing within the node, which means the proxy only 
  distributes the load to the pods on the on-site node. it is up to the external 
  balancer to solve the imbalance problem.

![](/img/posts/kube-proxy/externalTrafficPolicy-local.png)

# chains of iptables

Several chains of iptables are programed to do all kinds of filtering
and NAT between pods and services when a Service or Endpoint object is created.

- `KUBE-SERVICES` is the entry point for service packets. What it does is to match
  the destination IP:port and dispatch the packet to the corresponding KUBE-SVC-* 
  chain.
- `KUBE-SVC-*` acts as a load balancer, which distributes the packet to KUBE-SEP-* 
  chain. The number of KUBE-SEP-* is equal to the number of endpoints behind
  the service. Which KUBE-SEP-* to be chosen is determined randomly.
- `KUBE-SEP-*` represents a Service EndPoint. It simply does DNAT, replacing
  service IP:port with pod’s endpoint IP:Port.
- `KUBE-MARK-MASQ` adds a Netfilter mark to packets destined for the service which 
  originate outside the cluster’s network. Packets with this mark will be altered 
  in a POSTROUTING rule to use source network address translation (SNAT) with the 
  node’s IP address as their source IP address.
- `KUBE-MARK-DROP` adds a Netfilter mark to packets which do not have destination 
  NAT enabled by this point. These packets will be discarded in the KUBE-FIREWALL 
  chain.
- `KUBE-FW-*` chain acts while service is deployed with type LoadBalancer, it 
  matches the destination IP with service's loadbalancer IP and distributes the 
  packet to the corresponding KUBE-SVC-* chain(externalTrafficPolicy: Cluster) or
  KUBE-XLB-* chain (externalTrafficPolicy: Local).
- `KUBE-NODEPORTS` chain is occurred while service is deployed in the type of 
  NodePort and LoadBalancer. With it the external sources can access the service 
  by the node port. it matches the node port and distributes the 
  packet to the corresponding KUBE-SVC-* chain(externalTrafficPolicy: Cluster) or
  KUBE-XLB-* chain (externalTrafficPolicy: Local).
- `KUBE-XLB-*` chain works while externalTrafficPolicy is set to Local. With this
  chain programed, the packet is dropped if a node has no relevant endpoints 
  retained.
  


  
  
# References

[1] https://medium.com/pablo-perez/k8s-externaltrafficpolicy-local-or-cluster-40b259a19404
[2] https://www.asykim.com/blog/deep-dive-into-kubernetes-external-traffic-policies
[3] 