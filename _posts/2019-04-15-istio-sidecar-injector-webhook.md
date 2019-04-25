---
layout: post
title: "istio-sidecar-injector-webhook analysis"
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

## Initialization Procedure

First of all, let's look at the initialization procedure. sidecar-injector webhook uses
[spf13/cobra](<https://github.com/spf13/cobra>) to setup the CLI application. 

### flags

The flags of it are

```gotemplate
	flags = struct {
		loggingOptions *log.Options

		meshconfig          string # File containing the Istio mesh configuration (default "/etc/istio/config/mesh")
		injectConfigFile    string # File containing the Istio sidecar injection configuration and template (default "/etc/istio/inject/config")
		certFile            string
		privateKeyFile      string
		caCertFile          string
		port                int
		healthCheckInterval time.Duration
		healthCheckFile     string
		probeOptions        probe.Options
		kubeconfigFile      string
		webhookConfigName   string
		webhookName         string
	}
```

The two important configs are `meshconfig` and `injectConfigFile`, then let's inspect the pod specs
of sidecar-injector-webhook to figure out what they are:

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
```

As shown in the yaml specs, `meshConfig` is indicated as flag `meshConfig`, and it is a mounted
volume of [configmap `istio`](<https://serenafeng.github.io/2019/04/10/istio-sidecar-injector/#istio-configmap>),
while `injectConfigFile` is defined as flag `injectConfig`, and it is a volume of 
[`istio-sidecar-injector`](<https://serenafeng.github.io/2019/04/10/istio-sidecar-injector/#istio-sidecar-injector-configmap>).

### Webhook struct

The major structure of sidecar-injector is Webhook, it implements a mutating webhook for automatic
proxy injection.

```gotemplate
type Webhook struct {
	mu                     sync.RWMutex
	sidecarConfig          *Config
	sidecarTemplateVersion string
	meshConfig             *meshconfig.MeshConfig

	healthCheckInterval time.Duration
	healthCheckFile     string

	server     *http.Server
	meshFile   string
	configFile string
	watcher    *fsnotify.Watcher
	certFile   string
	keyFile    string
	cert       *tls.Certificate
}
```

- `sidecarConfig` is the content read from file `injectConfigFile`
- `meshConfig` is the content of file `meshConfig` and with default values applied
- `healthCheckInterval` frequency defined to update healthCheckFile
- `healthCheckFile` the file to be updated periodically, based on `healthCheckInterval` 
- `server` is the http server handle the event from route `/inject`
- `meshFile` is the `meshConfig` file
- `configFile` is the `injectConfigFile` file
- `watcher` is a [fsnotify](<https://github.com/howeyc/fsnotify>) watcher, it is a kind of
  notification system based on file system, any change under the watched directory/file will to
  notified to the watcher. Here the watcher is used to monitor the meshFile, configFile, certFile
  and keyFile, by doing so, any change of the configmap `istio`, `istio-sidecar-injector` happens
  will be detected and echoed by sidecar-injector webhook

### application initialization

The main work of root command is to create a mutating webhook, which is in charge of initializing
the `/inject` server and creating configuration watchers. 

```gotemplate
	rootCmd = &cobra.Command{
	    ......
		RunE: func(c *cobra.Command, _ []string) error {
		    ......
			wh, err := inject.NewWebhook(parameters)
			if err != nil {
				return multierror.Prefix(err, "failed to create injection webhook")
			}

			stop := make(chan struct{})
			if err := patchCertLoop(stop); err != nil {
				return multierror.Prefix(err, "failed to start patch cert loop")
			}

			go wh.Run(stop)
			cmd.WaitSignal(stop)
			return nil
		},
	}
```

`NewWebhook` creates a new instance of a mutating webhook for automatic sidecar injection, and
create a new watcher for monitoring meshConfig/InjectConfig/certFile/privateKeyFile files. 

```gotemplate
func NewWebhook(p WebhookParameters) (*Webhook, error) {

    // get the injectConfig and meshConfig from isttio-sidecar-injector and istio configmap
	sidecarConfig, meshConfig, err := loadConfig(p.ConfigFile, p.MeshFile)
	if err != nil {
		return nil, err
	}

    // create a watcher and monitor the configuration change
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err	
	}
	// watch the parent directory of the target files so we can catch
	// symlink updates of k8s ConfigMaps volumes.
	for _, file := range []string{p.ConfigFile, p.MeshFile, p.CertFile, p.KeyFile} {
		watchDir, _ := filepath.Split(file)
		if err := watcher.Watch(watchDir); err != nil {
			return nil, fmt.Errorf("could not watch %v: %v", file, err)
		}
	}

    // webhook definition
	wh := &Webhook{
	    ......
	}

    // initialize the http server and make it handle the event of route /inject
	// mtls disabled because apiserver webhook cert usage is still TBD.
	wh.server.TLSConfig = &tls.Config{GetCertificate: wh.getCert}
	h := http.NewServeMux()
	h.HandleFunc("/inject", wh.serveInject)
	wh.server.Handler = h

    return wh, nil
}
```

`patchCertLoop` is employed to update the CABundle field of the istio-sidecar-injector webhook
configuration, shown below:

```yaml
$ k g MutatingWebhookConfiguration istio-sidecar-injector -o yaml

apiVersion: admissionregistration.k8s.io/v1beta1
kind: MutatingWebhookConfiguration
metadata:
  labels:
  name: istio-sidecar-injector
  ......
webhooks:
- clientConfig:
    service:
      caBundle: xxxxxx
  ......
```

The `patchCertLoop` workflow is shown below, it is immature, the knowledge of `client-go` relevant
needs to be enriched or maybe corrected.

```gotemplate
func patchCertLoop(stopCh <-chan struct{}) error {
    // construct kubernetes client
	client, err := kube.CreateClientset(flags.kubeconfigFile, "")
	if err != nil {
		return err
	}
    // create a caCertFile monitoring watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	watchDir, _ := filepath.Split(flags.caCertFile)
	if err = watcher.Watch(watchDir); err != nil {
		return fmt.Errorf("could not watch %v: %v", flags.caCertFile, err)
	}
    // modify caBundle of the istio-sidecar-injector webhook
	if err = util.PatchMutatingWebhookConfig(client.AdmissionregistrationV1beta1().MutatingWebhookConfigurations(),
		flags.webhookConfigName, flags.webhookName, caCertPem); err != nil {
		return err
	}
    // create a controller to process the change event from istio-sidecar-injector webhook configuration
    // TODO, adding more detailed explaination after studying client-go
    // where is caCertPem come from in this case?
	watchlist := cache.NewListWatchFromClient(
		client.AdmissionregistrationV1beta1().RESTClient(),
		"mutatingwebhookconfigurations",
		"",
		fields.ParseSelectorOrDie(fmt.Sprintf("metadata.name=%s", flags.webhookConfigName)))
    _, controller := cache.NewInformer(
		watchlist,
		&v1beta1.MutatingWebhookConfiguration{},
		0,
		cache.ResourceEventHandlerFuncs{
			UpdateFunc: func(oldObj, newObj interface{}) {
				config := newObj.(*v1beta1.MutatingWebhookConfiguration)
				for i, w := range config.Webhooks {
					if w.Name == flags.webhookName && !bytes.Equal(config.Webhooks[i].ClientConfig.CABundle, caCertPem) {
						log.Infof("Detected a change in CABundle, patching MutatingWebhookConfiguration again")
						shouldPatch <- struct{}{}
						break
					}
				}
			},
		},
	)
	go controller.Run(stopCh)

	go func() {
		for {
			select {
            // event from monitoring webhook configuration
			case <-shouldPatch:
				doPatch(client, caCertPem)
            // event from monitoring caCertFile
			case <-watcher.Event:
				if b, err := ioutil.ReadFile(flags.caCertFile); err == nil {
					caCertPem = b
					doPatch(client, caCertPem)
				} else {
					log.Errorf("CA bundle file read error: %v", err)
				}
			}
		}
	}()
}
```

finally, implementing webhook server leveraging goroutine of `webserver.Run`. Basically, it includes 
three processes:
- start the webhook server, listen and process '/inject' event.
- periodically update `healthCheckFile`, to indicate webhook server is going on healthily. Typically,
  it is used in [probe](<https://serenafeng.github.io/2019/04/15/istio-sidecar-injector-webhook/#healthiness-detection>)
  command.
- update configuration based on the change of the four configuration files, to prevent frequent
  change of configuration files, a debounce timer is employed. 

```gotemplate
func (wh *Webhook) Run(stop <-chan struct{}) {
    // start webhook server
	go func() {
		if err := wh.server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		}
	}()
    // start the healthCheck timer
	var healthC <-chan time.Time
	if wh.healthCheckInterval != 0 && wh.healthCheckFile != "" {
		t := time.NewTicker(wh.healthCheckInterval)
		healthC = t.C
		defer t.Stop()
	}
    // define the debounce timer
	var timerC <-chan time.Time
    
	for {
		select {
		// debounce timer timeout, update the configurations
		case <-timerC:
		
		// some configuration file is changed, issue debounce timer
		case event := <-wh.watcher.Event:
			// use a timer to debounce configuration updates
			if (event.IsModify() || event.IsCreate()) && timerC == nil {
				timerC = time.After(watchDebounceDelay)
			}
		// healthCheck timer timeout, update healthCheck file
		case <-healthC:
			content := []byte(`ok`)
			if err := ioutil.WriteFile(wh.healthCheckFile, content, 0644); err != nil {
				log.Errorf("Health check update of %q failed: %v", wh.healthCheckFile, err)
			}
		}
	}
}
```

### healthiness detection

sidecar-injector implements a `probe` subcommand to check the liveness or readiness of the
locally-running sidecar-injector-webhook server. The configuration in pod's yaml is as below, 
`--prob-path` referencing to the aforementioned `healthCheckFile` during the healthCheck procedure.

```yaml
      livenessProbe:
        exec:
          command:
          - /usr/local/bin/sidecar-injector
          - probe
          - --probe-path=/health
          - --interval=4s
        failureThreshold: 3
        initialDelaySeconds: 4
        periodSeconds: 4
        successThreshold: 1
        timeoutSeconds: 1
      readinessProbe:
        exec:
          command:
          - /usr/local/bin/sidecar-injector
          - probe
          - --probe-path=/health
          - --interval=4s
        failureThreshold: 3
        initialDelaySeconds: 4
        periodSeconds: 4
        successThreshold: 1
        timeoutSeconds: 1
```

As previously mentioned that, `healthCheckFile` is updated periodically if the server is running
well. This feature is taken advantage by `probe` subcommand to detect the liveness and readiness of
the server by checking how long has the file being unmodified. If it is
shorter than specified update interval (defined by `--interval` option in the above), the webhook
server is judged to be successfully running. 

```gotemplate
// probe subcommand definition
	probeCmd = &cobra.Command{
		Use:   "probe",
		RunE: func(cmd *cobra.Command, args []string) error {
		    ......
			if err := probe.NewFileClient(&flags.probeOptions).GetStatus(); err != nil {
				return fmt.Errorf("fail on inspecting path %s: %v", flags.probeOptions.Path, err)
			}
			......
		},
	}

// file status check
func (fc *fileClient) GetStatus() error {
	stat, err := fc.statFunc(fc.opt.Path)
	if err != nil {
		return err
	}
	now := time.Now()
	// Sometimes filesystem / goroutine scheduling takes time, some buffer should be
	// allowed for the validity of a file.
	const jitter = 10 * time.Millisecond
	if mtime := stat.ModTime(); now.Sub(mtime) > fc.opt.UpdateInterval+jitter {
		return fmt.Errorf("file %s is too old (last modified time %v, should be within %v)", fc.opt.Path, mtime, fc.opt.UpdateInterval+jitter)
	}
	return nil
}
```

## Injection Procedure

As well known, the main work of sidecar-injector-webhook is to inject istio-init & istio-proxy
containers into istio mesh pod automatically, this is done by handling `/inject` http message.
 
When pod creation request comes, Kubernetes check auto injection is opened on the required namespace,
if so, it will send a injection request message to sidecar-injector-webhook (I guess so, to be
verified ^_^),  After receiving it, sidecar-injector-webhook begins to do the injection. The working 
function is `webhook.inject`.

The workflow mainly includes 3 steps:

- [inject or not](<https://serenafeng.github.io/2019/04/15/istio-sidecar-injector-webhook/#inject-or-not>).
  according to `sidecar.istio.io/inject` annotation, `neverInjectSelector`, 
  `alwaysInjectSelector` and `policy` settings, determine whether injection is required or not
- [get injection data](<https://serenafeng.github.io/2019/04/15/istio-sidecar-injector-webhook/#get-injection-data>).
  based on `meshConfig` and `podSpec` to render out a instance of
  `istio-sidecar-injector` configmap as the injection data.
- [patch podSpec](<https://serenafeng.github.io/2019/04/15/istio-sidecar-injector-webhook/#patch-podspec>).
  using the injection data out on the previous step, to patch the podSpec, adding
  istio sidecar related configurations, such as add or change annotations["sidecar.istio.io/status"],
  add `istio-init` initContainer, `istio-proxy` container. 

```gotemplate
func (wh *Webhook) inject(ar *v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
    ......
	if !injectRequired(ignoredNamespaces, wh.sidecarConfig, &pod.Spec, &pod.ObjectMeta) {
		return &v1beta1.AdmissionResponse{
			Allowed: true,
		}
	}

	// due to bug https://github.com/kubernetes/kubernetes/issues/57923,
	// k8s sa jwt token volume mount file is only accessible to root user, not istio-proxy(the user that istio proxy runs as).
	// workaround by https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-security-context-for-a-pod
	if wh.meshConfig.EnableSdsTokenMount && wh.meshConfig.SdsUdsPath != "" {
		var grp = int64(1337)
		pod.Spec.SecurityContext = &corev1.PodSecurityContext{
			FSGroup: &grp,
		}
	}

	spec, status, err := injectionData(wh.sidecarConfig.Template, wh.sidecarTemplateVersion, &pod.ObjectMeta, &pod.Spec, &pod.ObjectMeta, wh.meshConfig.DefaultConfig, wh.meshConfig) // nolint: lll
    ......

	annotations := map[string]string{annotationStatus.name: status}

	patchBytes, err := createPatch(&pod, injectionStatus(&pod), annotations, spec)
    ......

	return &reviewResponse
}
```

### inject or not

First of all, sidecar-injector-webhook checks whether the auto injection is allowed.

1. pod leveraging host network is not injected, the reason is explained in the code comment.

```gotemplate
	// Skip injection when host networking is enabled. The problem is
	// that the iptable changes are assumed to be within the pod when,
	// in fact, they are changing the routing at the host level. This
	// often results in routing failures within a node which can
	// affect the network provider within the cluster causing
	// additional pod failures.
	if podSpec.HostNetwork {
		return false
	}
```

2. special kubernetes system namespaces, such as kube-system and kube-public is not injected

```gotemplate
const (
	// NamespaceSystem is the system namespace where we place system components.
	NamespaceSystem string = "kube-system"
	// NamespacePublic is the namespace where we place public info (ConfigMaps)
	NamespacePublic string = "kube-public"
)

var ignoredNamespaces = []string{
	metav1.NamespaceSystem,
	metav1.NamespacePublic,
}

	// skip special kubernetes system namespaces
	for _, namespace := range ignored {
		if metadata.Namespace == namespace {
			return false
		}
	}
```

3. if `sidecar.istio.io/inject` annotation is not appeared in the pod spec, other default policies
   such as `neverInjectSelector`, `alwaysInjectSelector` or `policy` field will be checked. Or else,
   both `neverInjectSelector` and `alwaysInjectSelector` check are skipped, under any condition
   during `config.Policy` branch, `required = inject` will be returned, in this case, if
   `sidecar.istio.io/inject` is specified as "y", "yes", "true" or "on", `required=true` is return; 
   otherwise `required = nil` is returned, which means not inject. 

```gotemplate
	var useDefault bool
	var inject bool
	switch strings.ToLower(annotations[annotationPolicy.name]) {
	// http://yaml.org/type/bool.html
	case "y", "yes", "true", "on":
		inject = true
	case "":
		useDefault = true
	}

	var required bool
	switch config.Policy {
	case InjectionPolicyDisabled:
		if useDefault {
			required = false
		} else {
			required = inject
		}
	case InjectionPolicyEnabled:
		if useDefault {
			required = true
		} else {
			required = inject
		}
	}
``` 

4. if `sidecar.istio.io/inject` is not given, and `neverInjectorSelector` is matched, inject is
  set to be false, and `alwayInjectorSelector` is skipped. 
   
```gotemplate
	// If an annotation is not explicitly given, check the LabelSelectors, starting with NeverInject
	if useDefault {
		for _, neverSelector := range config.NeverInjectSelector {
			selector, err := metav1.LabelSelectorAsSelector(&neverSelector)
			if err != nil {
				log.Warnf("Invalid selector for NeverInjectSelector: %v (%v)", neverSelector, err)
			} else {
				if !selector.Empty() && selector.Matches(labels.Set(metadata.Labels)) {
					inject = false
					useDefault = false
					break
				}
			}
		}
	}

```

5. if `sidecar.istio.io/inject` is not given, and `neverInjectorSelector` is not matched,
   `alwayInjectorSelector` is checked. if match, inject is set to true.

```gotemplate
	// If there's no annotation nor a NeverInjectSelector, check the AlwaysInject one
	if useDefault {
		for _, alwaysSelector := range config.AlwaysInjectSelector {
			selector, err := metav1.LabelSelectorAsSelector(&alwaysSelector)
			if err != nil {
				log.Warnf("Invalid selector for AlwaysInjectSelector: %v (%v)", alwaysSelector, err)
			} else {
				if !selector.Empty() && selector.Matches(labels.Set(metadata.Labels)) {
					log.Debugf("Explicitly enabling injection for pod %s/%s due to pod labels matching AlwaysInjectSelector config map entry.",
						metadata.Namespace, potentialPodName(metadata))
					inject = true
					useDefault = false
					break
				}
			}
		}
	}
```

6. finally, if none of the above satisfied, here comes to `policy` check, if it it `enabled`, inject
   is required, or else, not inject

```gotemplate
	var required bool
	switch config.Policy {
	default: // InjectionPolicyOff
		log.Errorf("Illegal value for autoInject:%s, must be one of [%s,%s]. Auto injection disabled!",
			config.Policy, InjectionPolicyDisabled, InjectionPolicyEnabled)
		required = false
	case InjectionPolicyDisabled:
		if useDefault {
			required = false
		} else {
			required = inject
		}
	case InjectionPolicyEnabled:
		if useDefault {
			required = true
		} else {
			required = inject
		}
	}
```

### get injection data 

The major part of istio-sidecar-injector configmap used in injection is `template` field, the
rendered structure is:

```gotemplate
// SidecarInjectionSpec collects all container types and volumes for
// sidecar mesh injection
type SidecarInjectionSpec struct {
	// RewriteHTTPProbe indicates whether Kubernetes HTTP prober in the PodSpec
	// will be rewritten to be redirected by pilot agent.
	RewriteAppHTTPProbe bool                          `yaml:"rewriteAppHTTPProbe"`
	InitContainers      []corev1.Container            `yaml:"initContainers"`
	Containers          []corev1.Container            `yaml:"containers"`
	Volumes             []corev1.Volume               `yaml:"volumes"`
	DNSConfig           *corev1.PodDNSConfig          `yaml:"dnsConfig"`
	ImagePullSecrets    []corev1.LocalObjectReference `yaml:"imagePullSecrets"`
}
```

Now then, let's see how injection data is rendered.

1. The first step is to render the istio-sidecar-injector configmap into a template instance using
`podSpec` and `meshConfig`, for example in the configmap `--concurrency` field is defined as:

```yaml
  containers:
  - name: istio-proxy
    args:
    - proxy
    - sidecar
    ......
    [[ if gt .ProxyConfig.Concurrency 0 -]]
    - --concurrency
    - [[ .ProxyConfig.Concurrency ]]
    [[ end -]]
```

if `concurrency` field is set greater than 0, `--concurrency` will be set, or else, it is not given,
for example if `defaultConfig.concurrency: 2` is appeared in `meshConfig`, it is rendered as: 

```yaml
  containers:
  - name: istio-proxy
    args:
    - proxy
    - sidecar
    ......
    - --concurrency
    - 2
```

The implementation leveraging golang's template module, the code snippet is as below:

```gotemplate
    // configurations for rendering the istio-sidecar-injector configmap
	data := SidecarTemplateData{
		DeploymentMeta: deploymentMetadata,
		ObjectMeta:     metadata,
		Spec:           spec,
		ProxyConfig:    proxyConfig,
		MeshConfig:     meshConfig,
	}
    // functions used in template, for example 'annotation' function is used to set docker image
    // containers:
    // - name: istio-proxy
    //   image: [[ annotation .ObjectMeta `sidecar.istio.io/proxyImage`  "gcr.io/istio-release/proxyv2:release-1.1-latest-daily"  ]]
	funcMap := template.FuncMap{
		"formatDuration":      formatDuration,
		"isset":               isset,
		"excludeInboundPort":  excludeInboundPort,
		"includeInboundPorts": includeInboundPorts,
		"kubevirtInterfaces":  kubevirtInterfaces,
		"applicationPorts":    applicationPorts,
		"annotation":          annotation,
		"valueOrDefault":      valueOrDefault,
		"toJSON":              toJSON,
		"toJson":              toJSON, // Used by, e.g. Istio 1.0.5 template sidecar-injector-configmap.yaml
		"fromJSON":            fromJSON,
		"toYaml":              toYaml,
		"indent":              indent,
		"directory":           directory,
	}

	var tmpl bytes.Buffer
	temp := template.New("inject").Delims(sidecarTemplateDelimBegin, sidecarTemplateDelimEnd)
	t, err := temp.Funcs(funcMap).Parse(sidecarTemplate)
	if err != nil {
		log.Infof("Failed to parse template: %v %v\n", err, sidecarTemplate)
		return nil, "", err
	}
	if err := t.Execute(&tmpl, &data); err != nil {
		log.Infof("Invalid template: %v %v\n", err, sidecarTemplate)
		return nil, "", err
	}
```

2. Secondly, set concurrency of sidecar container, the workflow is already shown very clearly in
   function `applyConcurrency`.

```gotemplate
// applyConcurrency changes sidecar containers' concurrency to equals the cpu cores of the container
// if not set. It is inferred from the container's resource limit or request.
func applyConcurrency(containers []corev1.Container) {
	for i, c := range containers {
		if c.Name == ProxyContainerName {
			concurrency := extractConcurrency(&c)
			// do not change it when it is already set
			if concurrency > 0 {
				return
			}

			// firstly use cpu limits
			if !updateConcurrency(&containers[i], c.Resources.Limits.Cpu().MilliValue()) {
				// secondly use cpu requests
				updateConcurrency(&containers[i], c.Resources.Requests.Cpu().MilliValue())
			}
			return
		}
	}
}
```

In summary, the priority is:

```
    concurrency is not set -> container.Resources.Limits.Cpu is not set -> container.Resources.Requests.Cpu 
``` 

3. Finally, keep the rest things of `SidecarInjectionSpec` instance as it is, and compose
   "sidecar.istio.io/status" annotation:

```gotemplate
	status := &SidecarInjectionStatus{Version: version}
	for _, c := range sic.InitContainers {
		status.InitContainers = append(status.InitContainers, c.Name)
	}
	for _, c := range sic.Containers {
		status.Containers = append(status.Containers, c.Name)
	}
	for _, c := range sic.Volumes {
		status.Volumes = append(status.Volumes, c.Name)
	}
	for _, c := range sic.ImagePullSecrets {
		status.ImagePullSecrets = append(status.ImagePullSecrets, c.Name)
	}
	statusAnnotationValue, err := json.Marshal(status)
	if err != nil {
		return nil, "", fmt.Errorf("error encoded injection status: %v", err)
	}
```

### patch podSpec

the following things are included in the step.

- remove any things previously injected by kube-inject

```gotemplate
	// Remove any containers previously injected by kube-inject using
	// container and volume name as unique key for removal.
	patch = append(patch, removeContainers(pod.Spec.InitContainers, prevStatus.InitContainers, "/spec/initContainers")...)
	patch = append(patch, removeContainers(pod.Spec.Containers, prevStatus.Containers, "/spec/containers")...)
	patch = append(patch, removeVolumes(pod.Spec.Volumes, prevStatus.Volumes, "/spec/volumes")...)
	patch = append(patch, removeImagePullSecrets(pod.Spec.ImagePullSecrets, prevStatus.ImagePullSecrets, "/spec/imagePullSecrets")...)
```

- rewrite probes if `rewriteAppHTTPProbe` is set to `true` in istio sidecar-injector configmap, and
  the `livenessProbe` and/or `readinessProbe` is set in the original podSpec.
  For example, the original probe settings is shown below

```yaml
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: example
spec:
  template:
    spec:
      containers:
      - name: example
        livenessProbe:
          httpGet:
            path: /env/version
            port: 8999
          initialDelaySeconds: 4
          periodSeconds: 4
        readinessProbe:
          httpGet:
            path: /env/version
            port: 8999
          initialDelaySeconds: 5
          periodSeconds: 5
```
  if `rewriteAppHTTPProbe: true` is set, after injection, the probes will be rewritten to follow.
  Notice that, the path of livenessProbe and readinessProbe is different.

```yaml
  - env:
    - name: version
      value: v1
    name: example
    livenessProbe:
      failureThreshold: 3
      httpGet:
        path: /app-health/example/livez
        port: 15020
        scheme: HTTP
      initialDelaySeconds: 4
      periodSeconds: 4
      successThreshold: 1
      timeoutSeconds: 1
    readinessProbe:
      failureThreshold: 3
      httpGet:
        path: /app-health/example/readyz
        port: 15020
        scheme: HTTP
      initialDelaySeconds: 5
      periodSeconds: 5
      successThreshold: 1
      timeoutSeconds: 1
```
- patch podSpec with [injection data](<https://serenafeng.github.io/2019/04/15/istio-sidecar-injector-webhook/#get-injection-data>).

```gotemplate
	patch = append(patch, addContainer(pod.Spec.InitContainers, sic.InitContainers, "/spec/initContainers")...)
	patch = append(patch, addContainer(pod.Spec.Containers, sic.Containers, "/spec/containers")...)
	patch = append(patch, addVolume(pod.Spec.Volumes, sic.Volumes, "/spec/volumes")...)
	patch = append(patch, addImagePullSecrets(pod.Spec.ImagePullSecrets, sic.ImagePullSecrets, "/spec/imagePullSecrets")...)
```

- add DNSConfig if it is configured in istio-sidecar-injector configmap, like:

```yaml
{{- if .Values.global.podDNSSearchNamespaces }}
      dnsConfig:
        searches:
          {{- range .Values.global.podDNSSearchNamespaces }}
          - {{ . }}
          {{- end }}
{{- end }}
```

```gotemplate
	if sic.DNSConfig != nil {
		patch = append(patch, addPodDNSConfig(sic.DNSConfig, "/spec/dnsConfig")...)
	}
```

- add securityContext, if it is given in podSpec

```gotemplate
	if pod.Spec.SecurityContext != nil {
		patch = append(patch, addSecurityContext(pod.Spec.SecurityContext, "/spec/securityContext")...)
	}
```

- add or update "sidecar.istio.io/status" annotation to be like:
 
```yaml
 annotations:
   "sidecar.istio.io/status: '{"version":"6ca0d185f760e05bb8358127f2dd82304993c0d93edfb8609f7e397a18b14128","initContainers":["istio-init"],"containers":["istio-proxy"],"volumes":["istio-envoy","istio-certs"],"imagePullSecrets":null}'"
```
