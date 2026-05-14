package ingress

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/ingress/pkg/converter"
	"go.uber.org/zap"
	v1 "k8s.io/api/networking/v1"

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

// The default directive block is split into three slots so per-Ingress
// overrides can be injected at the position where they take effect:
//
//	corazaDirectivesPrefix    Coraza recommended config + default engine.
//	  ↳ rule-engine override goes here.
//	corazaDirectivesCRSSetup  CRS variable initialization.
//	  ↳ paranoia / anomaly-threshold setvars go here, so CRS phase:2
//	    rules see the overridden values when they evaluate.
//	corazaDirectivesCRSRules  CRS rule definitions.
//	  ↳ rule removals (by ID / by tag) and IP-block deny rules go here,
//	    after the rules they reference are loaded.
//
// Phase 1 ships in DetectionOnly so flagged requests are logged
// (audit logs → stdout → Promtail → Loki) but never blocked.
const (
	corazaDirectivesPrefix = `
Include @coraza.conf-recommended
SecRuleEngine DetectionOnly
`
	corazaDirectivesCRSSetup = `Include @crs-setup.conf.example
`
	corazaDirectivesCRSRules = `Include @owasp_crs/*.conf
`
)

// corazaDefaultDirectives is the directive block applied when no
// fine-grained or full overrides are set. Concatenation of the three
// slots in order.
const corazaDefaultDirectives = corazaDirectivesPrefix + corazaDirectivesCRSSetup + corazaDirectivesCRSRules

// fineGrainedCorazaAnnotations are the per-knob annotations whose
// presence is incompatible with the full coraza-directives override.
var fineGrainedCorazaAnnotations = []string{
	corazaRuleEngineAnnotation,
	corazaDisableRulesAnnotation,
	corazaDisableRulesByTagAnnotation,
	corazaParanoiaLevelAnnotation,
	corazaAnomalyThresholdInboundAnnotation,
	corazaAnomalyThresholdOutboundAnnotation,
	corazaBlockedIPsAnnotation,
}

// IngressHandler prepends a Coraza WAF handler to the route. Per-Ingress
// behavior is controlled through annotations declared in annotations.go:
//
//	coraza-disabled                      Skip the WAF for this Ingress.
//	coraza-directives                    Replace the default directive set.
//	coraza-rule-engine                   On | Off | DetectionOnly.
//	coraza-disable-rules                 Comma-separated rule IDs to remove.
//	coraza-disable-rules-by-tag          Comma-separated CRS tags to remove.
//	coraza-paranoia-level                1..4 (CRS paranoia level).
//	coraza-anomaly-threshold-inbound     Integer threshold.
//	coraza-anomaly-threshold-outbound    Integer threshold.
//	coraza-blocked-ips                   Comma-separated IPs/CIDRs to deny.
func (p CorazaPlugin) IngressHandler(input converter.IngressMiddlewareInput) (*caddyhttp.Route, error) {
	if getAnnotationBool(input.Ingress, corazaDisabledAnnotation, false) {
		return input.Route, nil
	}

	directives, err := buildCorazaDirectives(input.Ingress)
	if err != nil {
		return nil, err
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

// buildCorazaDirectives composes the directive block to send to the
// Coraza handler. If coraza-directives is set it replaces the default
// block entirely; any fine-grained annotations are ignored (with a
// warning logged so the misconfiguration is visible). Otherwise the
// default block is suffixed with directives derived from each fine-
// grained annotation in a stable order.
func buildCorazaDirectives(ing *v1.Ingress) (string, error) {
	if fullOverride := getAnnotation(ing, corazaDirectivesAnnotation); fullOverride != "" {
		if hasAnyFineGrainedCorazaAnnotation(ing) {
			caddy.Log().Named("ingress.coraza").Warn(
				"ingress sets both coraza-directives and fine-grained coraza-* annotations; fine-grained values ignored",
				zap.String("namespace", ing.Namespace),
				zap.String("name", ing.Name),
			)
		}
		return fullOverride, nil
	}

	var b strings.Builder
	b.WriteString(corazaDirectivesPrefix)

	if engine := getAnnotation(ing, corazaRuleEngineAnnotation); engine != "" {
		switch engine {
		case "On", "Off", "DetectionOnly":
			fmt.Fprintf(&b, "SecRuleEngine %s\n", engine)
		default:
			return "", fmt.Errorf("invalid value for %s/%s: %q (must be On, Off, or DetectionOnly)",
				annotationPrefix, corazaRuleEngineAnnotation, engine)
		}
	}

	b.WriteString(corazaDirectivesCRSSetup)

	if pl := getAnnotation(ing, corazaParanoiaLevelAnnotation); pl != "" {
		n, err := strconv.Atoi(pl)
		if err != nil || n < 1 || n > 4 {
			return "", fmt.Errorf("invalid value for %s/%s: %q (must be an integer in [1,4])",
				annotationPrefix, corazaParanoiaLevelAnnotation, pl)
		}
		// Raise both paranoia_level (which rules evaluate) and
		// blocking_paranoia_level (which rules actually block) so the
		// knob has the effect users expect from "make the WAF stricter".
		fmt.Fprintf(&b,
			`SecAction "id:90100,phase:1,nolog,pass,t:none,setvar:tx.paranoia_level=%d,setvar:tx.blocking_paranoia_level=%d"`+"\n",
			n, n)
	}

	if v := getAnnotation(ing, corazaAnomalyThresholdInboundAnnotation); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return "", fmt.Errorf("invalid value for %s/%s: %q (must be an integer)",
				annotationPrefix, corazaAnomalyThresholdInboundAnnotation, v)
		}
		fmt.Fprintf(&b,
			`SecAction "id:90110,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=%d"`+"\n", n)
	}

	if v := getAnnotation(ing, corazaAnomalyThresholdOutboundAnnotation); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return "", fmt.Errorf("invalid value for %s/%s: %q (must be an integer)",
				annotationPrefix, corazaAnomalyThresholdOutboundAnnotation, v)
		}
		fmt.Fprintf(&b,
			`SecAction "id:90111,phase:1,nolog,pass,t:none,setvar:tx.outbound_anomaly_score_threshold=%d"`+"\n", n)
	}

	b.WriteString(corazaDirectivesCRSRules)

	for _, id := range splitCSV(getAnnotation(ing, corazaDisableRulesAnnotation)) {
		fmt.Fprintf(&b, "SecRuleRemoveById %s\n", id)
	}

	for _, tag := range splitCSV(getAnnotation(ing, corazaDisableRulesByTagAnnotation)) {
		fmt.Fprintf(&b, "SecRuleRemoveByTag %s\n", tag)
	}

	if ips := splitCSV(getAnnotation(ing, corazaBlockedIPsAnnotation)); len(ips) > 0 {
		for _, ip := range ips {
			if err := validateIPOrCIDR(ip); err != nil {
				return "", fmt.Errorf("invalid entry in %s/%s: %w",
					annotationPrefix, corazaBlockedIPsAnnotation, err)
			}
		}
		// REMOTE_ADDR is the connection peer IP. Behind a cloud L7 LB
		// (without PROXY protocol or a server-level trusted_proxies +
		// client_ip_headers config), this is the LB IP, not the end-
		// user IP. To block end-user IPs, the deployment must either
		// enable PROXY protocol (configmap.proxyProtocol) or run with
		// the LB pre-translating the source IP.
		fmt.Fprintf(&b,
			`SecRule REMOTE_ADDR "@ipMatch %s" "id:90001,phase:1,deny,status:403,log,msg:'IP blocked by ingress annotation'"`+"\n",
			strings.Join(ips, ","))
	}

	return b.String(), nil
}

func hasAnyFineGrainedCorazaAnnotation(ing *v1.Ingress) bool {
	for _, a := range fineGrainedCorazaAnnotations {
		if getAnnotation(ing, a) != "" {
			return true
		}
	}
	return false
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func validateIPOrCIDR(s string) error {
	if strings.Contains(s, "/") {
		if _, err := netip.ParsePrefix(s); err != nil {
			return fmt.Errorf("not a valid CIDR %q: %w", s, err)
		}
		return nil
	}
	if _, err := netip.ParseAddr(s); err != nil {
		return fmt.Errorf("not a valid IP %q: %w", s, err)
	}
	return nil
}

func init() {
	converter.RegisterPlugin(CorazaPlugin{})
}

var (
	_ = converter.IngressMiddleware(CorazaPlugin{})
)
