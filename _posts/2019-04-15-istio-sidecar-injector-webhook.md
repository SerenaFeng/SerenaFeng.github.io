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

- `configFile` is the `injectConfigFile` file
- `meshFile` is the `meshConfig` file
- `sidecarConfig` is the content read from file `injectConfigFile`
- `meshConfig` is the content of file `meshConfig` and with default values applied
- `watcher` is a [fsnotify](<https://github.com/howeyc/fsnotify>) watcher, it is a kind of
  notification system based on file system, any change under the watched directory/file will to
  notified to the watcher. Here the watcher is used to monitor the meshFile, configFile, certFile
  and keyFile, by doing so, any change of the configmap `istio`, `istio-sidecar-injector` happens
  will be detected and echoed by sidecar-injector webhook
- `server` is the http server handle the event from route `/inject`

### startup the webhook

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
needs to be enriched or even corrected.

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

finally, implementing webhook server leveraging goroutine of `webserver.Run`. Basically, it implements
three processes:
- start the webhook server, listen and process '/inject' event.
- periodically update healthCheckFile, to indicate webhook server is going on healthily. Typically,
  it is used in `sidecar-injector probe` command.
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





