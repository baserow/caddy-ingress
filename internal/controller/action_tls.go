package controller

import (
	"os"
	"path/filepath"

	"github.com/caddyserver/ingress/internal/k8s"
	apiv1 "k8s.io/api/core/v1"
)

var certFolder = ""

// GetCertFolder returns the staging path for storing certificates as files.
func GetCertFolder() string {
	if certFolder == "" {
		// Use the systemd cache directory if possible.
		runtimeDir := os.Getenv("RUNTIME_DIRECTORY")
		if runtimeDir != "" {
			certFolder = filepath.Join(runtimeDir, "certs")
		} else {
			certFolder = filepath.FromSlash("/etc/caddy/certs")
		}
	}
	return certFolder
}

// SecretAddedAction provides an implementation of the action interface.
type SecretAddedAction struct {
	resource *apiv1.Secret
}

// SecretUpdatedAction provides an implementation of the action interface.
type SecretUpdatedAction struct {
	resource    *apiv1.Secret
	oldResource *apiv1.Secret
}

// SecretDeletedAction provides an implementation of the action interface.
type SecretDeletedAction struct {
	resource *apiv1.Secret
}

// onSecretAdded runs when a TLS secret resource is added to the cluster.
func (c *CaddyController) onSecretAdded(obj *apiv1.Secret) {
	if k8s.IsManagedTLSSecret(obj, c.resourceStore.Ingresses) {
		c.syncQueue.Add(SecretAddedAction{
			resource: obj,
		})
	}
}

// onSecretUpdated is run when a TLS secret resource is updated in the cluster.
func (c *CaddyController) onSecretUpdated(old *apiv1.Secret, new *apiv1.Secret) {
	if k8s.IsManagedTLSSecret(new, c.resourceStore.Ingresses) {
		c.syncQueue.Add(SecretUpdatedAction{
			resource:    new,
			oldResource: old,
		})
	}
}

// onSecretDeleted is run when a TLS secret resource is deleted from the cluster.
func (c *CaddyController) onSecretDeleted(obj *apiv1.Secret) {
	c.syncQueue.Add(SecretDeletedAction{
		resource: obj,
	})
}

// writeFile writes a secret to a .pem file on disk.
func writeFile(s *apiv1.Secret) error {
	content := make([]byte, 0)

	for _, cert := range s.Data {
		content = append(content, cert...)
	}

	err := os.WriteFile(filepath.Join(GetCertFolder(), s.Name+".pem"), content, 0644)
	if err != nil {
		return err
	}

	return nil
}

// forceNextReload clears the last-applied-config cache so the reload that
// follows this action is never skipped by the bytes.Equal short-circuit in
// reloadCaddy. Caddy only reads the cert folder (`load_folders`) at
// caddy.Load time, and a pem appearing on (or vanishing from) disk does not
// change the generated config JSON — without this, a Secret that lands
// after the Ingress-driven reload is silently never served. The ordering is
// deterministic on pod start: the TLS-secret informer only starts once an
// ingress with spec.tls is synced, so the pem is always written after the
// first config load.
func forceNextReload(c *CaddyController) {
	c.lastAppliedConfig = nil
}

func (r SecretAddedAction) handle(c *CaddyController) error {
	c.logger.Infof("TLS secret created (%s/%s)", r.resource.Namespace, r.resource.Name)
	if err := writeFile(r.resource); err != nil {
		return err
	}
	forceNextReload(c)
	return nil
}

func (r SecretUpdatedAction) handle(c *CaddyController) error {
	c.logger.Infof("TLS secret updated (%s/%s)", r.resource.Namespace, r.resource.Name)
	if err := writeFile(r.resource); err != nil {
		return err
	}
	forceNextReload(c)
	return nil
}

func (r SecretDeletedAction) handle(c *CaddyController) error {
	c.logger.Infof("TLS secret deleted (%s/%s)", r.resource.Namespace, r.resource.Name)
	if err := os.Remove(filepath.Join(GetCertFolder(), r.resource.Name+".pem")); err != nil {
		return err
	}
	forceNextReload(c)
	return nil
}

// watchTLSSecrets Start listening to TLS secrets if at least one ingress needs it.
// It will sync the CertFolder with TLS secrets
func (c *CaddyController) watchTLSSecrets() error {
	if c.informers.TLSSecret == nil && c.resourceStore.HasManagedTLS() {
		if err := os.MkdirAll(GetCertFolder(), 0755); err != nil && !os.IsExist(err) {
			return err
		}

		// Init informers
		params := k8s.TLSSecretParams{
			InformerFactory: c.factories.WatchedNamespace,
		}
		c.informers.TLSSecret = k8s.WatchTLSSecrets(params, k8s.TLSSecretHandlers{
			AddFunc:    c.onSecretAdded,
			UpdateFunc: c.onSecretUpdated,
			DeleteFunc: c.onSecretDeleted,
		})

		// Run it
		go c.informers.TLSSecret.Run(c.stopChan)

		// Sync secrets
		secrets, err := k8s.ListTLSSecrets(params, c.resourceStore.Ingresses)
		if err != nil {
			return err
		}

		for _, secret := range secrets {
			if err := writeFile(secret); err != nil {
				return err
			}
		}
	}

	return nil
}
