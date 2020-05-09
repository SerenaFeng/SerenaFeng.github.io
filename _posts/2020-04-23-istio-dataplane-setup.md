---
layout: post
title: Data Plane Setting Up in Istio
author: serena
head-style: text
tags: 
  - istio
  - istio-init
  - istio-cni-node
---

summary: in the post, we will profile how data plane is setup when Istio works
         both in simple Istio and CNI plugin mode. Concerning simple Istio, a 
         istio-init is injected into application Pod as initContainer and 
         configuring the traffic redirecting rules under the network namespace
         of the application pod. While for CNI plugin mode, istio-cni-node 
         component is leveraged for the setup work.

# tools

For the reason that initContainer is exited when completed, and other containers
may not have the permission to execute the `netstat` or `iptables`
command, so we use `nsenter` to show our configurations.

From the command `netstat`, we can see envoy listens on the following ports:

- 15006: outbound traffic from the pod/vm
- 15001: inbound traffic to the pod/vm
- 15090: Prometheus port
- 15020: health check port

```bash
cactus@master01:~$ sudo nsenter -t 28318 -n netstat -alp
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:15006           0.0.0.0:*               LISTEN      28359/envoy
tcp        0      0 0.0.0.0:http            0.0.0.0:*               LISTEN      28122/httpd
tcp        0      0 0.0.0.0:15090           0.0.0.0:*               LISTEN      28359/envoy
tcp        0      0 localhost:15000         0.0.0.0:*               LISTEN      28359/envoy
tcp        0      0 0.0.0.0:15001           0.0.0.0:*               LISTEN      28359/envoy
tcp6       0      0 10.244.241.67:15020     192.168.1.2:45336       TIME_WAIT   -
...
```

# Simple Istio Mode

Iptables rules are setup by running script
[istio-iptables.sh](<https://github.com/istio/istio/blob/release-1.4/tools/packaging/common/istio-iptables.sh>)
in initContainer 'istio-init', to be able to configure iptables, istio-init 
must be running under root and 'NET-ADMIN' privilege.

```yaml
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          add:
          - NET_ADMIN
          - NET_RAW
          drop:
          - ALL
        privileged: false
        readOnlyRootFilesystem: false
        runAsGroup: 0
        runAsNonRoot: false
        runAsUser: 0
```

Configured iptables chains&rules are shown below:

```bash
cactus@master01:~$ docker ps | grep echo
16335332b8b5        a4912a7fd5d1             "/usr/local/bin/pilo…"   22 hours ago        Up 22 hours                             k8s_istio-proxy_echo-b87c57997-t4c4v_default_4eb3fa95-5872-4984-9227-ca09ab2cd37d_0
596031e0106f        httpd                    "httpd-foreground"       22 hours ago        Up 22 hours                             k8s_echo_echo-b87c57997-t4c4v_default_4eb3fa95-5872-4984-9227-ca09ab2cd37d_0
6178f3d79776        k8s.gcr.io/pause:3.1     "/pause"                 22 hours ago        Up 22 hours                             k8s_POD_echo-b87c57997-t4c4v_default_4eb3fa95-5872-4984-9227-ca09ab2cd37d_0

cactus@master01:~$ docker inspect 163 --format '{{.State.Pid}}'
28318

cactus@master01:~$ sudo nsenter -t 28318 -n iptables -t nat -S
-P PREROUTING ACCEPT
-P INPUT ACCEPT
-P OUTPUT ACCEPT
-P POSTROUTING ACCEPT
-N ISTIO_INBOUND
-N ISTIO_IN_REDIRECT
-N ISTIO_OUTPUT
-N ISTIO_REDIRECT
-A PREROUTING -p tcp -j ISTIO_INBOUND
-A OUTPUT -p tcp -j ISTIO_OUTPUT
-A ISTIO_INBOUND -p tcp -m tcp --dport 22 -j RETURN
-A ISTIO_INBOUND -p tcp -m tcp --dport 15020 -j RETURN
-A ISTIO_INBOUND -p tcp -j ISTIO_IN_REDIRECT
-A ISTIO_IN_REDIRECT -p tcp -j REDIRECT --to-ports 15006
-A ISTIO_OUTPUT -s 127.0.0.6/32 -o lo -j RETURN
-A ISTIO_OUTPUT ! -d 127.0.0.1/32 -o lo -j ISTIO_IN_REDIRECT
-A ISTIO_OUTPUT -m owner --uid-owner 1337 -j RETURN
-A ISTIO_OUTPUT -m owner --gid-owner 1337 -j RETURN
-A ISTIO_OUTPUT -d 127.0.0.1/32 -j RETURN
-A ISTIO_OUTPUT -j ISTIO_REDIRECT
-A ISTIO_REDIRECT -p tcp -j REDIRECT --to-ports 15001
```

# Istio with CNI plugin

In this mode, the process includes 2 steps -- plugin installation and iptables 
configuration.

## installing plugin

The installation is performed by istio-cni-node component, which is a DaemonSet.
For each pod of initialized istio-cni-node includes 2 containers:

- 'intall-cni' container executes `install-cni.sh` to prepare the executable files 
  of istio-cni, istio-cni-repair and istio-iptables.sh, the cni plugin config file 
  such as '10-calico.conflist', and the kubeconfig file 'ZZZ-istio-cni-kubeconfig' 
  for istio-cni service account. In the end, it also periodically checks whether 
  istio-cni plugin is in place all along.
- 'repair-cni' container executes `istio-cni-repair` command, the main purpose is
  to label pod with 'cni.istio.io/uninitialized: true' when initContainer 
  'istio-validation' fails.

## configuring iptables

Rules of iptables are configured by executing script 'istio-iptables.sh', which is
driven by kubelet by running 'istio-cni' plugin. The configured chains and rules
are the same to simple istio mode.

When a pod is initializing, it firstly waits and checks whether the routing rules
are in place by injecting and running initContainer 'istio-validation'.

