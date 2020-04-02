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
echo-75548f949f-6hg97   1/1     Running   0          100s   10.244.122.1     minion03   <none>           <none>
echo-75548f949f-7r575   1/1     Running   0          100s   10.244.50.68     minion01   <none>           <none>
echo-75548f949f-h5h6w   1/1     Running   0          100s   10.244.193.193   minion02   <none>           <none>
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

Starting from chain KUBE-SERVICES, all inbound traffics to service echo(matched by
destination IP 10.104.16.232 and port 6711), will be processed by two rules:

  1) the source IP of the packet not comes from pod is substituted with node IP when 
     going through chain KUBE-MARK-MASQ
  2) then, the packet flows into chain KUBE-SVC-U52O5CQH2XXNVZ54

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




# Further inspect:

1. ClusterIP with external ip


# References
ip a
[1] https://medium.com/pablo-perez/k8s-externaltrafficpolicy-local-or-cluster-40b259a19404
[2] https://www.asykim.com/blog/deep-dive-into-kubernetes-external-traffic-policies
[3] 
