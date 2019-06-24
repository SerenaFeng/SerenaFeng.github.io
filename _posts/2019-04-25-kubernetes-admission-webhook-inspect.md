---
layout: post
title: Kubernetes Admission Webhook Inspect
subtitle: How Admission Webhook works in Kubernetes
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

MutatingAdmissionWebhook together with ValidatingAdmissionWebhook are a special kind of admission
controllers, with them, Kubernetes cluster administrators can create additional mutating and
validating admission plugins to the admission chain of apiserver without recompiling them. 
The difference between them is pretty self-explanatory: validating may reject a request,
but they may not modify the object they are receiving in the admission request. While mutating may 
modify objects by creating a patch that sent back in the admission response. If any of the webhook 
controller rejects the request, an error will be returned to the end-user.

After configuring MutatingAdmissionWebhook and ValidatingAdmissionWebhook, the API request lifecycle
of Kubernetes is as below:

![](/img/posts/kubernetes-api-lifecycle.png)

# How admission webhook works?

For mutating webhook, it intercepts requests matching the rules defined in MutatingWebhookConfiguration
before persisting into ETCD. MutatingAdmissionWebhokk executes the mutation by sending admission
request to mutating webhook server, which is just a plain http server adhere to Kubernetes API.

Similarly, for validating webhook, it intercepts requests matching the rules defined in
ValidatingWebhookConfiguration before persisting into ETCD. ValidatingAdmissionWebhook executes the
validation by sending admission request to validating webhook server, which as well a plain http server.

So, to make the admission webhook function, four objects are involved:

## XXXWebhookConfiguration

XXXWebhookConfiguration is employed to register XXXAdmissionWebhook in the apiserver. it states:

- How to communicate with the webhook admission server
- Rules describes what operations on what resources/subresources the webhook will handle
- How unrecognized errors from the admission endpoint are handled
- Whether to run the webhook on an object based on namespace selector.
- Whether this webhook has side effects

The structure is as below:

```gotemplate
type XXXWebhookConfiguration struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	Webhooks []Webhook
}
type Webhook struct {
	Name string
	ClientConfig WebhookClientConfig
	Rules []RuleWithOperations
	FailurePolicy *FailurePolicyType
	NamespaceSelector *metav1.LabelSelector
	SideEffects *SideEffectClass
	TimeoutSeconds *int32
	AdmissionReviewVersions []string
}
```

## XXXAdmissionWebhook 

`To be precised`

XXXAdmissionWebhook is a plugin-style admission controller that can be configured into
the apiserver. The XXXAdmissionWebhook plugin get the list of interested admission webhooks from
XXXWebhookConfiguration. Then the XXXAdmissionWebhook controller observes the requests to apiserver
and intercepts requests matching the rules in admission webhooks and calls them in parallel.

This step is done automatically by Kubernetes

## XXX webhook server

Webhook Admission Server is just plain http server that adhere to Kubernetes API. For each request
to the apiserver, the admission webhook sends an admissionReview(API for reference) to the
relevant webhook server. The webhook server gathers information like object, oldobject, and userInfo
from admissionReview, and sends back a admissionReview response including AdmissionResponse whose
Allowed and/or Result fields are filled with the admission decision and optional Patch to mutate or
validate the resources.

The basic concept is:

![](/img/posts/webhook-concepts.png)

1. Kubernetes submits an AdmissionReview to your webhook, containing an AdmissionRequest, which has
   - a UID
   - a Raw Extension carrying full json payload for an object, such as a Pod
   - And other stuff that you may or may not use
2. Based on this information you apply your logic and return a new AdmissionReview. The
   AdmissionReview contains an AdmissionResponse which has
   - the original UID from the AdmissionRequest
   - A Patch (if applicable)
   - The Allowed field which is either true or false

The structures of AdmissionReview AdmissionRequest and AdmissionResponse are:

```gotemplate
// AdmissionReview describes an admission review request/response.
type AdmissionReview struct {
	metav1.TypeMeta

	// Request describes the attributes for the admission request.
	// +optional
	Request *AdmissionRequest

	// Response describes the attributes for the admission response.
	// +optional
	Response *AdmissionResponse
}
```
```gotemplate
// AdmissionRequest describes the admission.Attributes for the admission request.
type AdmissionRequest struct {
	// UID is an identifier for the individual request/response. It allows us to distinguish instances of requests which are
	// otherwise identical (parallel requests, requests when earlier requests did not modify etc)
	// The UID is meant to track the round trip (request/response) between the KAS and the WebHook, not the user request.
	// It is suitable for correlating log entries between the webhook and apiserver, for either auditing or debugging.
	UID types.UID
	// Kind is the type of object being manipulated.  For example: Pod
	Kind metav1.GroupVersionKind
	// Resource is the name of the resource being requested.  This is not the kind.  For example: pods
	Resource metav1.GroupVersionResource
	// SubResource is the name of the subresource being requested.  This is a different resource, scoped to the parent
	// resource, but it may have a different kind. For instance, /pods has the resource "pods" and the kind "Pod", while
	// /pods/foo/status has the resource "pods", the sub resource "status", and the kind "Pod" (because status operates on
	// pods). The binding resource for a pod though may be /pods/foo/binding, which has resource "pods", subresource
	// "binding", and kind "Binding".
	// +optional
	SubResource string
	// Name is the name of the object as presented in the request.  On a CREATE operation, the client may omit name and
	// rely on the server to generate the name.  If that is the case, this method will return the empty string.
	// +optional
	Name string
	// Namespace is the namespace associated with the request (if any).
	// +optional
	Namespace string
	// Operation is the operation being performed
	Operation Operation
	// UserInfo is information about the requesting user
	UserInfo authentication.UserInfo
	// Object is the object from the incoming request prior to default values being applied
	// +optional
	Object runtime.Object
	// OldObject is the existing object. Only populated for UPDATE requests.
	// +optional
	OldObject runtime.Object
	// DryRun indicates that modifications will definitely not be persisted for this request.
	// Calls to webhooks must have no side effects if DryRun is true.
	// Defaults to false.
	// +optional
	DryRun *bool
}
```

```gotemplate
// AdmissionResponse describes an admission response.
type AdmissionResponse struct {
	// UID is an identifier for the individual request/response.
	// This should be copied over from the corresponding AdmissionRequest.
	UID types.UID
	// Allowed indicates whether or not the admission request was permitted.
	Allowed bool
	// Result contains extra details into why an admission request was denied.
	// This field IS NOT consulted in any way if "Allowed" is "true".
	// +optional
	Result *metav1.Status
	// Patch contains the actual patch. Currently we only support a response in the form of JSONPatch, RFC 6902.
	// +optional
	Patch []byte
	// PatchType indicates the form the Patch will take. Currently we only support "JSONPatch".
	// +optional
	PatchType *PatchType
	// AuditAnnotations is an unstructured key value map set by remote admission controller (e.g. error=image-blacklisted).
	// MutatingAdmissionWebhook and ValidatingAdmissionWebhook admission controller will prefix the keys with
	// admission webhook name (e.g. imagepolicy.example.com/error=image-blacklisted). AuditAnnotations will be provided by
	// the admission webhook to add additional context to the audit log for this request.
	// +optional
	AuditAnnotations map[string]string
}
```

# Creating and deploying an admission webhook

Since we have covered the basic theory, let's try out the admission webhooks in a real
cluster. In this example we will create a mutating and a validating webhook servers, 
deploy them on a cluster, then create and deploy the corresponding webhook configurations
to see if they work as expected.

When a pod creation is required, for the mutating webhook, if 'version' environment variable of it
is 'v1', the "webhook.example.com/allow: false" annotation will be patched, or else the 
"webhook.example.com/allow: true" is added. While in the validating webhook, if
"webhook.example.com/allow: true" annotation meets, the pod creation is accepted, otherwise rejected.

[Our project](<https://github.com/SerenaFeng/k8s-webhook-example>) reference Istio
sidecar-injector-webhook a lot.

## Prerequisite

To make the webhook function, firstly, MutatingAdmissionWebhook and/or ValidatingAdmissionWebhook
plugin must be enabled, it is enabled by default, to confirm this, run the following command, and
check they are appeared in the output.

```bash
kube-apiserver -h | grep enable-admission-plugins
```

To double enable it in case the implementation of Kubernetes changes, you can add it in
`--enable-admission-plugins` explicitly while starting up kube-apiserver.

```bash
kube-apiserver --enable-admission-plugins=......,MutatingAdmissionWebhook,ValidatingAdmissionWebhook
```

or, if admission webhooks are not wanted for sure, you can disable them by adding to
`--disable-admission-plugins` option.

```bash
kube-apiserver --disable-admission-plugins=......,MutatingAdmissionWebhook,ValidatingAdmissionWebhook
```

Besides enabling the plugins, admissionregistration.k8s.io/v1beta1 API should to enabled as well.
Ensure that by checking:

```bash
kubectl api-versions | grep admissionregistration.k8s.io/v1beta1
```
## Writing webhook server

Now then, let's write our webhook server.

### Mutating webhook

It is a plain http server that listen on the path '/mutate'. When a pod creation is required, the
mutating webhook server will check if the 'version' environment variable is 'v1',
if so, the annotation patching will be skipped, otherwise "webhook.example.com/allow: true" is
patched in the annotation field.

```gotemplate
func mutateRequired(podSpec *corev1.PodSpec, metadata *metav1.ObjectMeta) bool {
    // skip mutating on v1
	for _, env := range podSpec.Containers[0].Env {
		if env.Name == "version" && env.Value == "v1" {
			log.V(2).Infof("version v1 is not mutated\n")
			return false
		}
	}

	return true
}

func doMutate(podName string, pod *corev1.Pod) *v1beta1.AdmissionResponse {
	if !mutateRequired(&pod.Spec, &pod.ObjectMeta) {
		log.V(4).Infof("Skipping %s/%s due to policy check", pod.ObjectMeta.Namespace, podName)
		return &v1beta1.AdmissionResponse{
			Allowed: true,
		}
	}

    // patch annotation
	annotations := map[string]string{webhookAnnotationAllowKey: "true"}
	patchBytes, err := createPatch(pod, annotations)
	if err != nil {
		log.V(2).Infof("AdmissionResponse: err=%v\n", err)
		return toAdmissionResponse(err)
	}

	log.V(4).Infof("AdmissionResponse: patch=%v\n", string(patchBytes))

	reviewResponse := v1beta1.AdmissionResponse{
		Allowed: true,
		Patch:   patchBytes,
		PatchType: func() *v1beta1.PatchType {
			pt := v1beta1.PatchTypeJSONPatch
			return &pt
		}(),
	}
	return &reviewResponse
}

func createPatch(pod *corev1.Pod, annotations map[string]string) ([]byte, error) {
	var patch []PatchOperation
	patch = append(patch, updateAnnotation(pod.Annotations, annotations)...)
	return json.Marshal(patch)
}

func updateAnnotation(target map[string]string, added map[string]string) (patch []PatchOperation) {
	for key, value := range added {
		if target == nil {
			target = map[string]string{}
			patch = append(patch, PatchOperation{
				Op:   "add",
				Path: "/metadata/annotations",
				Value: map[string]string{
					key: value,
				},
			})
		} else {
			op := "add"
			if target[key] != "" {
				op = "replace"
			}
			patch = append(patch, PatchOperation{
				Op:    op,
				Path:  "/metadata/annotations/" + escapeJSONPointerValue(key),
				Value: value,
			})
		}
	}
	return patch
}
```

### Validating webhook

It listens on the path '/validate'. When a pod creation is required, the
validating webhook server will check if the annotation "webhook.example.com/allow: true" is given,
if not, reject the creation.

```gotemplate
func doValidate(podName string, pod *corev1.Pod) *v1beta1.AdmissionResponse {
	if !validateRequired(&pod.ObjectMeta) {
		log.V(4).Infof("Rejecting %s/%s due to policy check", pod.ObjectMeta.Namespace, podName)
		return &v1beta1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Reason: "required annotation are not set",
			},
		}
	}

	reviewResponse := v1beta1.AdmissionResponse{
		Allowed: true,
	}

	return &reviewResponse
}

func validateRequired(metadata *metav1.ObjectMeta) bool {
	for k, v := range metadata.Annotations {
		if k == webhookAnnotationAllowKey && v == "true" {
			return true
		}
	}

	return false
}
```

## Generate the CertificateSignedRequest

Both mutating and validating webhook leverage HTTPS connection. Here, we’ll reuse the
[script](<https://gist.github.com/denji/12b3a568f092ab951456>) originally written by the Istio team
to generate a certificate signing request. Then we’ll send the request to the Kubernetes API, fetch
the certificate, and create the required secret from the result. 

In our case [create-signed-certs.sh](<https://github.com/SerenaFeng/k8s-webhook-example/blob/master/install/helm/we/templates/create-signed-cert.sh.tpl>)
script is leveraged to generate the csr and create the required secret, which will be executed
in the `InitContainer`.

Once the secret is created, we can create deployment and service. Up until this point we’ve
produced nothing but an HTTP server that’s accepting requests through a service on port 443.

## Get caBundle

To let the `apiserver` trusts the TLS certificate of the webhook server, the CA certificate should
be provided to the webhook configuration. the official explanation of `caBundle` in the comment of
the source code is:

```gotemplate
	// `caBundle` is a PEM encoded CA bundle which will be used to validate the webhook's server certificate.
	// If unspecified, system trust roots on the apiserver are used.
	// +optional
	CABundle []byte
```

Because we’ve signed our certificates with the Kubernetes API, we can use the CA cert from our
`kubeconfig` to simplify things. The script to get the `caBundle` is as below: 

```bash
$ CABundle=$(kubectl config view --raw --minify --flatten -o jsonpath='{.clusters[].cluster.certificate-authority-data}')
```

ToDo: More information about the caBundle.

## Define the MutatingWebhookConfiguration

```yaml
apiVersion: admissionregistration.k8s.io/v1beta1
kind: MutatingWebhookConfiguration
metadata:
  name: mutateexample
  namespace: webhook
  labels:
    app: mutateexample
webhooks:
  - name: mutateexample.webhook.svc
    clientConfig:
      service:
        name: mutateexample
        namespace: webhook
        path: "/mutate"
      caBundle: ${caBundle}
    rules:
      - operations: [ "CREATE" ]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
    failurePolicy: Fail
    namespaceSelector:
      matchLabels:
        webhook-example: enabled
```

## Define the ValidatingWebhookConfiguration

```yaml
apiVersion: admissionregistration.k8s.io/v1beta1
kind: ValidatingWebhookConfiguration
metadata:
  name: validateexample
  namespace: webhook
  labels:
    app: validateexample
webhooks:
  - name: validateexample.webhook.svc
    clientConfig:
      service:
        name: validateexample
        namespace: webhook
        path: "/validate"
      caBundle: ${caBundle}
    rules:
      - operations: [ "CREATE" ]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
    failurePolicy: Fail
    namespaceSelector:
      matchLabels:
        webhook-example: enabled
```



# References

- [Diving into Kubernetes MutatingAdmissionWebhook](<https://medium.com/ibm-cloud/diving-into-kubernetes-mutatingadmissionwebhook-6ef3c5695f74>)
- [In-depth introduction to Kubernetes admission webhooks](<https://banzaicloud.com/blog/k8s-admission-webhooks/>)
- [Some Admission Webhook Basics](<https://container-solutions.com/some-admission-webhook-basics/>)