package ingress

import (
	"encoding/json"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/ingress/pkg/converter"

	// Side-effect import: registers the `http.handlers.waf` Caddy module.
	// The corazaModule struct is unexported upstream, so we emit the
	// handler config as raw JSON below rather than referencing the type.
	_ "github.com/corazawaf/coraza-caddy/v2"
)

// CorazaPlugin injects a Coraza WAF handler at the start of every
// generated route's handler chain. Priority 100 places this plugin
// ahead of redirect/rewrite (10) and reverseproxy (-10), so the WAF
// inspects every request before any other handler runs.
type CorazaPlugin struct{}

func (p CorazaPlugin) IngressPlugin() converter.PluginInfo {
	return converter.PluginInfo{
		Name:     "ingress.coraza",
		Priority: 100,
		New:      func() converter.Plugin { return new(CorazaPlugin) },
	}
}

// corazaDefaultDirectives is applied when no per-Ingress override is
// set. Phase 1 ships in DetectionOnly so flagged requests are logged
// (audit logs → stdout → Promtail → Loki) but never blocked.
const corazaDefaultDirectives = `
Include @coraza.conf-recommended
SecRuleEngine DetectionOnly
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
`

// IngressHandler prepends a Coraza WAF handler to the route. Per-Ingress
// overrides are exposed via two annotations:
//
//	caddy.ingress.kubernetes.io/coraza-disabled: "true"
//	  Skip the WAF for this Ingress entirely.
//
//	caddy.ingress.kubernetes.io/coraza-directives: <directives>
//	  Replace the default directive set (e.g. flip to SecRuleEngine On
//	  per-route during a phased rollout).
func (p CorazaPlugin) IngressHandler(input converter.IngressMiddlewareInput) (*caddyhttp.Route, error) {
	if getAnnotationBool(input.Ingress, corazaDisabledAnnotation, false) {
		return input.Route, nil
	}

	directives := getAnnotation(input.Ingress, corazaDirectivesAnnotation)
	if directives == "" {
		directives = corazaDefaultDirectives
	}

	cfg := map[string]any{
		"handler":        "waf",
		"directives":     directives,
		"load_owasp_crs": true,
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}

	input.Route.HandlersRaw = append(input.Route.HandlersRaw, raw)
	return input.Route, nil
}

func init() {
	converter.RegisterPlugin(CorazaPlugin{})
}

var (
	_ = converter.IngressMiddleware(CorazaPlugin{})
)
