package global

import (
	"encoding/json"
	"fmt"

	caddy2 "github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/caddyserver/ingress/pkg/converter"
	"github.com/caddyserver/ingress/pkg/store"
	"github.com/mholt/acmez/v3/acme"
)

type ConfigMapPlugin struct{}

func init() {
	converter.RegisterPlugin(ConfigMapPlugin{})
}

func (p ConfigMapPlugin) IngressPlugin() converter.PluginInfo {
	return converter.PluginInfo{
		Name: "configmap",
		New:  func() converter.Plugin { return new(ConfigMapPlugin) },
	}
}

func (p ConfigMapPlugin) GlobalHandler(config *converter.Config, store *store.Store) error {
	cfgMap := store.ConfigMap

	tlsApp := config.GetTLSApp()
	httpServer := config.GetHTTPServer()

	if cfgMap.Debug {
		config.Logging.Logs = map[string]*caddy2.CustomLog{"default": {BaseLog: caddy2.BaseLog{Level: "DEBUG"}}}
	}

	if cfgMap.AcmeCA != "" || cfgMap.Email != "" {
		acmeIssuer := caddytls.ACMEIssuer{}

		if cfgMap.AcmeCA != "" {
			acmeIssuer.CA = cfgMap.AcmeCA
		}

		if cfgMap.AcmeEABKeyID != "" && cfgMap.AcmeEABMacKey != "" {
			acmeIssuer.ExternalAccount = &acme.EAB{
				KeyID:  cfgMap.AcmeEABKeyID,
				MACKey: cfgMap.AcmeEABMacKey,
			}
		}

		if cfgMap.Email != "" {
			acmeIssuer.Email = cfgMap.Email
		}

		var onDemandConfig *caddytls.OnDemandConfig
		if cfgMap.OnDemandTLS {
			if cfgMap.OnDemandAsk == "" {
				return fmt.Errorf("onDemandTLS requires onDemandAsk to be set: Caddy v2.7+ requires a permission endpoint to enable on-demand TLS for public ACME issuers")
			}
			onDemandConfig = &caddytls.OnDemandConfig{
				PermissionRaw: caddyconfig.JSONModuleObject(
					caddytls.PermissionByHTTP{Endpoint: cfgMap.OnDemandAsk},
					"module", "http", nil,
				),
			}
		}

		tlsApp.Automation = &caddytls.AutomationConfig{
			OnDemand:          onDemandConfig,
			OCSPCheckInterval: cfgMap.OCSPCheckInterval,
			Policies: []*caddytls.AutomationPolicy{
				{
					IssuersRaw: []json.RawMessage{
						caddyconfig.JSONModuleObject(acmeIssuer, "module", "acme", nil),
					},
					OnDemand: cfgMap.OnDemandTLS,
				},
			},
		}
	}

	if cfgMap.ProxyProtocol {
		// Without an allow list Caddy strips the PROXY header but discards
		// its contents (fallback policy "ignore"), so the logged client IP
		// stays the load balancer's. Only sources in proxyProtocolAllow are
		// trusted to assert a client IP — scope it to the LB's subnet.
		ppWrapper := map[string]any{"wrapper": "proxy_protocol"}
		if len(cfgMap.ProxyProtocolAllow) > 0 {
			ppWrapper["allow"] = cfgMap.ProxyProtocolAllow
		}
		ppRaw, err := json.Marshal(ppWrapper)
		if err != nil {
			return fmt.Errorf("marshaling proxy_protocol listener wrapper: %w", err)
		}
		httpServer.ListenerWrappersRaw = []json.RawMessage{
			ppRaw,
			json.RawMessage(`{"wrapper":"tls"}`),
		}
	}

	// Trust an upstream proxy layer (e.g. Cloudflare in front of the LB) to
	// assert the real client IP via a request header. Only connections whose
	// source address — after the proxy_protocol listener wrapper has applied
	// the LB's PROXY header — falls inside trustedProxies get their client IP
	// taken from clientIPHeaders (in order); anyone else sending the header
	// is ignored, so direct clients can't spoof it. This populates Caddy's
	// client_ip var, which coraza-caddy prefers over RemoteAddr — WAF rules
	// on REMOTE_ADDR, the IP blocklists, and logs all see the real client.
	if len(cfgMap.TrustedProxies) > 0 {
		httpServer.TrustedProxiesRaw = caddyconfig.JSONModuleObject(
			caddyhttp.StaticIPRange{Ranges: cfgMap.TrustedProxies},
			"source", "static", nil,
		)
		httpServer.ClientIPHeaders = cfgMap.ClientIPHeaders
	}
	return nil
}

// Interface guards
var (
	_ = converter.GlobalMiddleware(ConfigMapPlugin{})
)
