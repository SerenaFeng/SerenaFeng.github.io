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

summary: in Kubernetes, a Service is a L4(TCP/UDP/SCTP) load balancer, it uses the 
         DNAT to redirect inbound traffic to backend pods. The redirecting is performed 
         by kube-proxy, which sits on every node. In this post, we will introduce when 
         working in iptables mode, how kube-proxy handles the forwarding of traffics.

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

- only available on NodePort and LoadBalancer service.
- packets are not SNAT'd for either inter-cluster or external traffic.
- when the packet comes to a no-pod-retain node, it gets dropped, which avoids
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

# [Workflow of kube-proxy iptables](https://docs.google.com/drawings/d/1MtWL8qRTs6PlnJrW4dh8135_S9e2SaawT410bJuoBPk)

![](/img/posts/kube-proxy/kube-proxy_iptables.png)

# Practices

Now that we have the basic concept of kube-proxy in mind, let's explain them in 
practice. 

Since LoadBalance is not support in the cluster, the practices will only focus
on NodePort & ClusterIP this time.

## environment

Our testing cluster is deployed using [cactus](https://github.com/serenafeng/cactus),
the kubernetes version is v1.17.3, setting up 4 VMs(1 masters, 3 workers) with the lab 
definition [pod11](https://github.com/serenafeng/cactus/config/lab). 
The network setup is shown below:

- DNS domain: basic.k8s
- PodIP CIDR: 10.244.0.0/16
- ClusterIP CIDR: 10.96.0.0/12

The pod backends are managed by a deployment `echo` with 3 pod replicas. 

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: echo
  name: echo
spec:
  replicas: 3
  selector:
    matchLabels:
      app: echo
  template:
    metadata:
      labels:
        app: echo
    spec:
      containers:
      - image: k8s.gcr.io/echoserver:1.4
        name: echoserver
```

To simulate the in-cluster communications and for debug purpose, we also set up a 
debug pod in leveraging image `nicolaka/netshoot:latest`, which is widely used
in [kubectl-debug](https://github.com/aylei/kubectl-debug) 

```bash
kubectl run -it --rm --restart=Never debug --image=nicolaka/netshoot:latest sh
``` 

The environment looks like:

```bash
serena@ubuntu:~$ virsh list
 Id    Name                           State
----------------------------------------------------
 216   basic_master01                 running
 217   basic_minion01                 running
 218   basic_minion02                 running
 219   basic_minion03                 running

serena@ubuntu:~$ kubectl get po -l app=echo -o wide
NAME                    READY   STATUS    RESTARTS   AGE    IP               NODE       NOMINATED NODE   READINESS GATES
debug                   1/1     Running   0          10h    10.244.193.194   minion02   <none>           <none>
echo-75548f949f-6hg97   1/1     Running   0          100s   10.244.122.1     minion03   <none>           <none>
echo-75548f949f-7r575   1/1     Running   0          100s   10.244.50.68     minion01   <none>           <none>
echo-75548f949f-h5h6w   1/1     Running   0          100s   10.244.193.193   minion02   <none>           <none>

serena@ubuntu:~$ kubectl get node -o wide
NAME       STATUS   ROLES    AGE   VERSION   INTERNAL-IP    EXTERNAL-IP   OS-IMAGE             KERNEL-VERSION      CONTAINER-RUNTIME
master01   Ready    master   23h   v1.17.3   192.168.11.2   <none>        Ubuntu 18.04.4 LTS   4.15.0-88-generic   docker://18.9.7
minion01   Ready    <none>   22h   v1.17.3   192.168.11.3   <none>        Ubuntu 18.04.4 LTS   4.15.0-88-generic   docker://18.9.7
minion02   Ready    <none>   22h   v1.17.3   192.168.11.4   <none>        Ubuntu 18.04.4 LTS   4.15.0-88-generic   docker://18.9.7
minion03   Ready    <none>   22h   v1.17.3   192.168.11.5   <none>        Ubuntu 18.04.4 LTS   4.15.0-88-generic   docker://18.9.7
```

## ClusterIP

With different configurations, in the following, we will discuss 5 type of ClusterIP
services:

- normal: a minimal service definition, with available pod backends, and not headless 
  service
- session affinity: 
- external ip
- no endpoints
- headless

### normal service

A simple ClusterIP Service definition is like:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: echo
spec:
  ports:
  - port: 6711
    targetPort: 8080
  selector:
    app: echo
```

Kubernetes creates a service called 'echo', and automatically creates 3 endpoints
pointing to 3 echo pods respectively.

```bash
serena@ubuntu:~$ kubectl get svc echo
NAME   TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)    AGE
echo   ClusterIP   10.98.124.225   <none>        6711/TCP   89s

serena@ubuntu:~$ kubectl get ep echo
NAME   ENDPOINTS                                                 AGE
echo   10.244.122.1:8080,10.244.193.193:8080,10.244.50.68:8080   107s
```

Cluster IP is a virtual IP, it doesn't have an entity, kubernetes registers DNS
records by associating the service name to it. For each service, kubernetes generates
4 dns records: svc-name, svc-name.namespace, svc-name.namespace.svc, 
svc-name.namespace.svc.domain. 
In this case echo/echo.default/echo.default.svc/echo.default.svc.basic.k8s
are associated with service 'echo'. From the debugging pod, we can see:

```bash
/ # nslookup echo
Server:		10.96.0.10
Address:	10.96.0.10:53

Name:   echo.default.svc.basic.k8s
Address: 10.98.124.225

/ # dig @10.96.0.10 echo +search +short
10.98.124.225
```

If namespace is not specified, dns server attaches the namespace from the source pod,
if accessing a service of the other namespace is required, we should attach namespace 
obviously. For instance, nslookup-ing 'echo' service in 'extra' namespace will be like:

```bash
serena@ubuntu:~$ kubectl get svc -n extra
NAME   TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)    AGE
echo   ClusterIP   10.106.152.64   <none>        6711/TCP   64m

/ # nslookup echo.extra
Server:         10.96.0.10
Address:        10.96.0.10#53

Name:   echo.extra.svc.basic.k8s
Address: 10.106.152.64
```

To make service's cluster IP accessible from external network as well as from pod 
network, kube-proxy creates several chains and rules. 

```bash
cactus@master01:~$ sudo iptables -t nat -S | grep KUBE-SERVICES
-N KUBE-SERVICES
-A PREROUTING -m comment --comment "kubernetes service portals" -j KUBE-SERVICES
-A OUTPUT -m comment --comment "kubernetes service portals" -j KUBE-SERVICES
...

cactus@master01:~$ sudo iptables -t nat -L KUBE-SERVICES | grep echo
Chain KUBE-SERVICES (2 references)
target                     prot  opt  source          destination         
KUBE-MARK-MASQ  tcp  -- !10.244.0.0/16        10.98.124.225        /* default/echo: cluster IP */ tcp dpt:6711
KUBE-SVC-U52O5CQH2XXNVZ54  tcp  --  anywhere             10.98.124.225        /* default/echo: cluster IP */ tcp dpt:6711

cactus@master01:~$ sudo iptables -t nat -L KUBE-SVC-U52O5CQH2XXNVZ54
Chain KUBE-SVC-U52O5CQH2XXNVZ54 (1 references)
target     prot opt source               destination         
KUBE-SEP-EXCZZIFMC3FTGK26  all  --  anywhere             anywhere             statistic mode random probability 0.33333333349
KUBE-SEP-KRPRU4V5NQPJR2QF  all  --  anywhere             anywhere             statistic mode random probability 0.50000000000
KUBE-SEP-PYQWLFFOR4OGUSWB  all  --  anywhere             anywhere            

cactus@master01:~$ sudo iptables -t nat -L KUBE-SEP-EXCZZIFMC3FTGK26
Chain KUBE-SEP-EXCZZIFMC3FTGK26 (1 references)
target     prot opt source               destination         
KUBE-MARK-MASQ  all  --  10.244.122.1         anywhere            
DNAT       tcp  --  anywhere             anywhere             tcp to:10.244.122.1:8080

cactus@master01:~$ sudo iptables -t nat -L KUBE-SEP-KRPRU4V5NQPJR2QF
Chain KUBE-SEP-KRPRU4V5NQPJR2QF (1 references)
target     prot opt source               destination         
KUBE-MARK-MASQ  all  --  10.244.193.193       anywhere            
DNAT       tcp  --  anywhere             anywhere             tcp to:10.244.193.193:8080

cactus@master01:~$ sudo iptables -t nat -L KUBE-SEP-PYQWLFFOR4OGUSWB
Chain KUBE-SEP-PYQWLFFOR4OGUSWB (1 references)
target     prot opt source               destination         
KUBE-MARK-MASQ  all  --  10.244.50.68         anywhere            
DNAT       tcp  --  anywhere             anywhere             tcp to:10.244.50.68:8080
```

__KUBE-SERVICES__

From the chains of PREROUTING and OUTPUT we can see, all data packets incoming or
outgoing of Pods enters the chain KUBE-SERVICES as the starting point, in this case,
all inbound traffics come into service echo(matched by
destination IP 10.104.16.232 and port 6711), will be processed by two rules in ordinal:

  1) the source IP of the packet not comes from pod is substituted with node IP when 
     going through chain KUBE-MARK-MASQ

  2) then, the packet flows into chain KUBE-SVC-U52O5CQH2XXNVZ54

From below we can see, when accessing the service externally(not from pods), the source 
IP is replaced with nodeIP; 

```bash
cactus@master01:~$ curl --interface 192.168.11.2 -s 10.101.220.97:8711 | grep client
client_address=10.244.241.64

cactus@master01:~$ sudo conntrack -L -d 10.101.220.97
tcp      6 117 TIME_WAIT src=192.168.11.2 dst=10.101.220.97 sport=47153 dport=8711 src=10.244.122.1 dst=10.244.241.64 sport=8080 dport=24678 [ASSURED] mark=0 use=1
```

when the packet comes from the internal pod--the 'debug' pod, the source IP
remains it is. 

```bash
bash-5.0# curl -s 10.101.220.97:8711 | grep client
client_address=10.244.193.194
```

__KUBE-SVC-*__

In the chain KUBE-SVC-U52O5CQH2XXNVZ54, the load balancing between pods is performed 
by iptables module 'statistic'. It distributes packet to KUBE-SEP-* randomly with the
'probability' setting.

__KUBE-SEP-*__

Each KUBE-SEP-* chain represents a pod or endpoint respectively. It includes two actions:

  1) packet escaping from the pod is source NAT-ed with host's docker0 IP.
  2) packet coming into the pod is DNAT-ed with pod's ip, then routes to the backend pod.


### session affinity service

Kubernetes supports ClientIP based session affinity, session affinity makes sure that
requests from the same particular client are passed to the same backend server, 
which means pod in kubernetes.

A session affinity service is defined as:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: echo-session
spec:
  sessionAffinity: ClientIP
  ports:
  - port: 6711
    targetPort: 8080
  selector:
    app: echo
```

After creating the service in kubernetes, a service and endpoint are created:

```bash
serena@ubuntu:~$ kubectl get svc echo-session
NAME           TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)    AGE
echo-session   ClusterIP   10.109.153.82   <none>        6711/TCP   16s

serena@ubuntu:~$ kubectl get ep echo-session
NAME           ENDPOINTS                                                 AGE
echo-session   10.244.122.1:8080,10.244.193.193:8080,10.244.50.68:8080   26s
``` 

The difference between 'normal' ClusterIP and ClusterIP with session affinity is
beside distributing requests coming into the service for the first time leveraging 
'statistic' iptables module, kube-proxy will also apply 'recent' module for not the
first time visitors, the timeout checkout time is 10800s by default. it can be reset 
by `service.spec.sessionAffinityConfig.clientIP.timeoutSeconds`. The iptables
configurations look like below:

```bash
cactus@master01:~$ sudo iptables -t nat  -L KUBE-SERVICES | grep echo-session
KUBE-MARK-MASQ  tcp  -- !10.244.0.0/16        10.109.153.82        /* default/echo-session: cluster IP */ tcp dpt:6711
KUBE-SVC-NPPZ32WH6LRMQBHN  tcp  --  anywhere             10.109.153.82        /* default/echo-session: cluster IP */ tcp dpt:6711

cactus@master01:~$ sudo iptables -t nat  -L KUBE-SVC-NPPZ32WH6LRMQBHN
Chain KUBE-SVC-NPPZ32WH6LRMQBHN (1 references)
target     prot opt source               destination         
KUBE-SEP-XHJZRVA3S6MYRZW7  all  --  anywhere             anywhere             recent: CHECK seconds: 10800 reap name: KUBE-SEP-XHJZRVA3S6MYRZW7 side: source mask: 255.255.255.255
KUBE-SEP-GCFXO5QV6K3OGUQA  all  --  anywhere             anywhere             recent: CHECK seconds: 10800 reap name: KUBE-SEP-GCFXO5QV6K3OGUQA side: source mask: 255.255.255.255
KUBE-SEP-PMGN3E23UUMYGBZ3  all  --  anywhere             anywhere             recent: CHECK seconds: 10800 reap name: KUBE-SEP-PMGN3E23UUMYGBZ3 side: source mask: 255.255.255.255
KUBE-SEP-XHJZRVA3S6MYRZW7  all  --  anywhere             anywhere             statistic mode random probability 0.33333333349
KUBE-SEP-GCFXO5QV6K3OGUQA  all  --  anywhere             anywhere             statistic mode random probability 0.50000000000
KUBE-SEP-PMGN3E23UUMYGBZ3  all  --  anywhere             anywhere            

cactus@master01:~$ sudo iptables -t nat  -L KUBE-SEP-XHJZRVA3S6MYRZW7
Chain KUBE-SEP-XHJZRVA3S6MYRZW7 (2 references)
target     prot opt source               destination         
KUBE-MARK-MASQ  all  --  10.244.122.1         anywhere            
DNAT       tcp  --  anywhere             anywhere             recent: SET name: KUBE-SEP-XHJZRVA3S6MYRZW7 side: source mask: 255.255.255.255 tcp to:10.244.122.1:8080

cactus@master01:~$ sudo iptables -t nat  -L KUBE-SEP-GCFXO5QV6K3OGUQA
Chain KUBE-SEP-GCFXO5QV6K3OGUQA (2 references)
target     prot opt source               destination         
KUBE-MARK-MASQ  all  --  10.244.193.193       anywhere            
DNAT       tcp  --  anywhere             anywhere             recent: SET name: KUBE-SEP-GCFXO5QV6K3OGUQA side: source mask: 255.255.255.255 tcp to:10.244.193.193:8080

cactus@master01:~$ sudo iptables -t nat  -L KUBE-SEP-PMGN3E23UUMYGBZ3
Chain KUBE-SEP-PMGN3E23UUMYGBZ3 (2 references)
target     prot opt source               destination         
KUBE-MARK-MASQ  all  --  10.244.50.68         anywhere            
DNAT       tcp  --  anywhere             anywhere             recent: SET name: KUBE-SEP-PMGN3E23UUMYGBZ3 side: source mask: 255.255.255.255 tcp to:10.244.50.68:8080
```

### external ip service

> If there are external IPs that route to one or more cluster nodes, Kubernetes 
  Services can be exposed on those externalIPs. Traffic that ingresses into the 
  cluster with the external IP (as destination IP), on the Service port, will be 
  routed to one of the Service endpoints.

In our environment, '172.0.11.33' is a ip located on node master01, can be accessed 
externally, considering it as an external ip, the service is defined:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: echo-extip
spec:
  ports:
  - port: 8711
    targetPort: 8080
  selector:
    app: echo
  externalIPs:
  - 172.0.11.33
```

so, the service and endpoint is:

```bash
serena@ubuntu:~$ kubectl get svc echo-extip
NAME         TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)    AGE
echo-extip   ClusterIP   10.105.77.232   172.0.11.33   8711/TCP   27m

serena@ubuntu:~$ kubectl get ep echo-extip
NAME         ENDPOINTS                                                 AGE
echo-extip   10.244.122.1:8080,10.244.193.193:8080,10.244.50.68:8080   27m
```

The corresponding rules in the chain KUBE-SERVICES are as below, due to the 
chains of KUBE-SVC- and KUBE-SEP- is very similar to normal service, we will not
show them thereafter:

```bash
cactus@master01:~$ sudo iptables -t nat  -L KUBE-SERVICES | grep echo-extip
KUBE-MARK-MASQ  tcp  -- !10.244.0.0/16        10.105.77.232        /* default/echo-extip: cluster IP */ tcp dpt:8711
KUBE-SVC-DDLWINQFLEZGGMTH  tcp  --  anywhere             10.105.77.232        /* default/echo-extip: cluster IP */ tcp dpt:8711
KUBE-MARK-MASQ  tcp  --  anywhere             172.0.11.33          /* default/echo-extip: external IP */ tcp dpt:8711
KUBE-SVC-DDLWINQFLEZGGMTH  tcp  --  anywhere             172.0.11.33             /* default/echo-extip: external IP */ tcp dpt:8711 PHYSDEV match ! --physdev-is-in ADDRTYPE match src-type !LOCAL
KUBE-SVC-DDLWINQFLEZGGMTH  tcp  --  anywhere             172.0.11.33             /* default/echo-extip: external IP */ tcp dpt:8711 ADDRTYPE match dst-type LOCAL
```

The first two chains works just a normal service, after SNAT operation, goes into chain 
KUBE-SVC- for load balancing. 

Next 3 chains is unique to the external ip type. It employs `physdev` module to identify
traffics from bridge device and perform NAT operation. The second rule from the bottom
denotes requests from neither local nor bridge interface are passed in to chain KUBE-SVC
for load balancing.

### no endpoint service

A cluster IP is always associated with backend pods by `selector`. If no pod matches
Service's selector, the service will be created with no endpoints referring to it, 
in that case, there will be no iptables rules created for routing traffics. 

The wrong selector case:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: echo-noep
spec:
  ports:
  - port: 8711
    targetPort: 8080
  selector:
    app: echo-noep
```

The created service, endpoint and iptables rules would be:

```bash
serena@ubuntu:~$ kubectl get svc echo-noep
NAME        TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)    AGE
echo-noep   ClusterIP   10.96.42.131   <none>        8711/TCP   19m
serena@ubuntu:~$ kubectl get ep echo-noep
NAME        ENDPOINTS   AGE
echo-noep   <none>      19m

cactus@master01:~$ sudo iptables-save -t nat | grep echo-noep
cactus@master01:~$ 
```

And if a Service has no selector defined, the endpoint would be not created at all.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: echo-nosel
spec:
  ports:
  - port: 8711
    targetPort: 8080
```
```bash
serena@ubuntu:~$ kubectl get svc
NAME            TYPE        CLUSTER-IP       EXTERNAL-IP                 PORT(S)    AGE
echo-nosel      ClusterIP   10.109.105.198   <none>                      8711/TCP   21m
kubernetes      ClusterIP   10.96.0.1        <none>                      443/TCP    18h

serena@ubuntu:~$ kubectl get ep
NAME            ENDPOINTS                                                 AGE
kubernetes      10.0.11.2:6443                                            18h
```

### headless service

> Sometimes you don’t need load-balancing and a single Service IP. In this case, you can 
  create what are termed “headless” Services, by explicitly specifying "None" for the 
  cluster IP (.spec.clusterIP).

The headless service definition of 'echo' is:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: echo-headless
spec:
  clusterIP: None
  ports:
  - port: 9711
    targetPort: 8080
  selector:
    app: echo
```

After `kubectl apply`, the service controller and endpoint controller will create
the following objects:

```bash
serena@ubuntu:~$ kubectl get svc echo-headless
NAME            TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)    AGE
echo-headless   ClusterIP   None            <none>        9711/TCP   8s

serena@ubuntu:~$ kubectl get ep echo-headless
NAME            ENDPOINTS                                                 AGE
echo-headless   10.244.122.1:8080,10.244.193.193:8080,10.244.50.68:8080   10s
```

However, from iptables, no chains or rules is created, by checking DNS records, 
shows it uses pod's IP directly.

```bash
bash-5.0# dig echo-headless +search +short
10.244.50.68
10.244.193.193
10.244.122.1
```

## NodePort

Kubernetes exposes service with nodeIP:nodePort by deploying NodePort type service,
by doing so, kubernetes creates a ClusterIP service, to which the NodePort service will
route, and meanwhile opens a specific port(node port) on all the Nodes, and any 
traffic that is sent to this port is forwarded to destination pod.

The entry point of iptables rules for performing NodePort trafficing is '-A KUBE-SERVICES 
-m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in 
this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS', this rule is the last one 
in KUBE-SERVICES chain, it indicates that if a visiting packet is not matched by any of 
the anterior rules, it is forwarded into KUBE-NODEPORTS chain for further processing.

```bash
cactus@master01:~$ sudo iptables -t nat -L KUBE-SERVICES
Chain KUBE-SERVICES (2 references)
target     prot opt source               destination         
.
.
.
KUBE-NODEPORTS  all  --  anywhere             anywhere             /* kubernetes service nodeports; NOTE: this must be the last rule in this chain */ ADDRTYPE match dst-type LOCAL
```

In the following subsection, we will discuss 2 types of NodePort service:

- default service(externalTrafficPolicy: Cluster)
- externalTrafficPolicy: Local

## default NodePort service

A NodePort service with no customization would create an `externalTrafficPolicy: Cluster`
type service. The manifest is written in below:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: echo-np
spec:
  type: NodePort
  ports:
  - port: 8711
    targetPort: 8080
  selector:
    app: echo
```

The service and endpoints are created:

```bash
serena@ubuntu:~$ kubectl get svc echo-np
NAME      TYPE       CLUSTER-IP      EXTERNAL-IP   PORT(S)          AGE
echo-np   NodePort   10.107.142.56   <none>        8711:30398/TCP   84s
serena@ubuntu:~$ kubectl get ep echo-np
NAME      ENDPOINTS                                                 AGE
echo-np   10.244.122.1:8080,10.244.193.193:8080,10.244.50.68:8080   88s
```

As we can see from the above, the port 30398 is assigned to the service 'echo-np'.
On each node, kube-proxy allocating a listening port for it:

```bash
cactus@master01:~$ sudo netstat -alnp | grep 30398
tcp6       0      0 :::30398                :::*                    LISTEN      4406/kube-proxy     

cactus@master01:~$ ps -p 4406 -o args
COMMAND
/usr/local/bin/kube-proxy --config=/var/lib/kube-proxy/config.conf --hostname-override=master01
```

From iptables' perspective, each two sets of chains & rules are added to the chain
KUBE-SERVICES & KUBE-NODEPORTS separately:

```bash
cactus@master01:~$ sudo iptables -t nat -L KUBE-SERVICES | grep echo-np
KUBE-MARK-MASQ  tcp  -- !10.244.0.0/16        10.107.142.56        /* default/echo-np: cluster IP */ tcp dpt:8711
KUBE-SVC-2JCTU37Y3EPLWMDU  tcp  --  anywhere             10.107.142.56        /* default/echo-np: cluster IP */ tcp dpt:8711

cactus@master01:~$ sudo iptables -t nat -L KUBE-NODEPORTS
Chain KUBE-NODEPORTS (1 references)
target     prot opt source               destination         
KUBE-MARK-MASQ  tcp  --  anywhere             anywhere             /* default/echo-np: */ tcp dpt:30398
KUBE-SVC-2JCTU37Y3EPLWMDU  tcp  --  anywhere             anywhere             /* default/echo-np: */ tcp dpt:30398
```

Regarding KUBE-SERVICES chain, it is used for the cluster ip accessing, for detailed
information, please reference 'normal ClusterIP service'.

KUBE-NODEPORTS denotes that all packets accessing port 30398, firstly is SNAT-ed, then
goes into KUBE-SVC chain for load balancing to select a pod to route to.

### externalTrafficPolicy: Local

Using "externalTrafficPolicy: Local" will preserve source IP and drop packets from node 
has no local endpoint. It is defined as:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: echo-local
spec:
  ports:
  - port: 8711
    targetPort: 8080
  selector:
    app: echo
  type: NodePort
  externalTrafficPolicy: Local
```

service and endpoints created:

```bash
serena@ubuntu:~$ kubectl get svc echo-local
NAME         TYPE       CLUSTER-IP      EXTERNAL-IP   PORT(S)          AGE
echo-local   NodePort   10.103.249.21   <none>        8711:30757/TCP   45s

serena@ubuntu:~$ kubectl get ep echo-local
NAME         ENDPOINTS                                                 AGE
echo-local   10.244.122.1:8080,10.244.193.193:8080,10.244.50.68:8080   53s
```

The chain of KUBE-NODEPORTS is different between the nodes have local endpoints and 
those haven't. in our cluster, 'echo' pod is not scheduled on master01 node, so
when we trying to access the service by master01's nodeIP, the packet will be dropped
by the rule '-A KUBE-XLB-WVR3FY6OQL4XX3DZ -m comment --comment "default/echo-local: 
has no local endpoints" -j KUBE-MARK-DROP'. On the contrary, when accessing the
service by minion01's nodeIP, it will be forwarded to pod 'echo-75548f949f-7r575'(which
is scheduled on minion01 node) directly, by rule '-A KUBE-XLB-WVR3FY6OQL4XX3DZ -m comment 
--comment "Balancing rule 0 for default/echo-local:" -j KUBE-SEP-FO5ZQ232FWC5GK4A'

The chains and rules on the pod-owned nodes is look like:

```bash
cactus@ubuntu:~$ sudo iptables -t nat -L KUBE-NODEPORTS
Chain KUBE-NODEPORTS (1 references)
target     prot opt source               destination         
KUBE-MARK-MASQ  tcp  --  anywhere             anywhere             /* default/echo-np: */ tcp dpt:30398
KUBE-SVC-2JCTU37Y3EPLWMDU  tcp  --  anywhere             anywhere             /* default/echo-np: */ tcp dpt:30398
KUBE-MARK-MASQ  tcp  --  localhost/8          anywhere             /* default/echo-local: */ tcp dpt:30757
KUBE-XLB-WVR3FY6OQL4XX3DZ  tcp  --  anywhere             anywhere             /* default/echo-local: */ tcp dpt:30757

cactus@ubuntu:~$ sudo iptables -t nat -L KUBE-XLB-WVR3FY6OQL4XX3DZ
Chain KUBE-XLB-WVR3FY6OQL4XX3DZ (1 references)
target     prot opt source               destination         
KUBE-SVC-WVR3FY6OQL4XX3DZ  all  --  10.244.0.0/16        anywhere             /* Redirect pods trying to reach external loadbalancer VIP to clusterIP */
KUBE-MARK-MASQ  all  --  anywhere             anywhere             /* masquerade LOCAL traffic for default/echo-local: LB IP */ ADDRTYPE match src-type LOCAL
KUBE-SVC-WVR3FY6OQL4XX3DZ  all  --  anywhere             anywhere             /* route LOCAL traffic for default/echo-local: LB IP to service chain */ ADDRTYPE match src-type LOCAL
KUBE-SEP-FO5ZQ232FWC5GK4A  all  --  anywhere             anywhere             /* Balancing rule 0 for default/echo-local: */
```

No pod retained nodes:

```bash
cactus@master01:~$ sudo iptables -t nat -L KUBE-NODEPORTS
Chain KUBE-NODEPORTS (1 references)
target     prot opt source               destination         
KUBE-MARK-MASQ  tcp  --  anywhere             anywhere             /* default/echo-np: */ tcp dpt:30398
KUBE-SVC-2JCTU37Y3EPLWMDU  tcp  --  anywhere             anywhere             /* default/echo-np: */ tcp dpt:30398
KUBE-MARK-MASQ  tcp  --  localhost/8          anywhere             /* default/echo-local: */ tcp dpt:30757
KUBE-XLB-WVR3FY6OQL4XX3DZ  tcp  --  anywhere             anywhere             /* default/echo-local: */ tcp dpt:30757

cactus@master01:~$ sudo iptables -t nat -L KUBE-XLB-WVR3FY6OQL4XX3DZ
Chain KUBE-XLB-WVR3FY6OQL4XX3DZ (1 references)
target     prot opt source               destination         
KUBE-SVC-WVR3FY6OQL4XX3DZ  all  --  10.244.0.0/16        anywhere             /* Redirect pods trying to reach external loadbalancer VIP to clusterIP */
KUBE-MARK-MASQ  all  --  anywhere             anywhere             /* masquerade LOCAL traffic for default/echo-local: LB IP */ ADDRTYPE match src-type LOCAL
KUBE-SVC-WVR3FY6OQL4XX3DZ  all  --  anywhere             anywhere             /* route LOCAL traffic for default/echo-local: LB IP to service chain */ ADDRTYPE match src-type LOCAL
KUBE-MARK-DROP  all  --  anywhere             anywhere             /* default/echo-local: has no local endpoints */
```

Accessing from master01's node IP is forbiddened, but not for minion01. And from
minion01's response we can see source IP is not SNAT-ed by nodeIP.

```bash
serena@ubuntu:~$ wget -qO - 192.168.11.2:30757 | grep client
^C

serena@ubuntu:~$ wget -qO - 192.168.11.3:30757 | grep client
client_address=192.168.11.1
```

# Further inspect:

1. ClusterIP with external ip(physdev module of iptables deep dive)

# References

- [A Deep Dive into Kubernetes External Traffic Policies](https://www.asykim.com/blog/deep-dive-into-kubernetes-external-traffic-policies)
- [Kubernetes Services and Iptables](https://msazure.club/kubernetes-services-and-iptables/)

