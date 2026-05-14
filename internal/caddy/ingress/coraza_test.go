package ingress

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/ingress/pkg/converter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// extractCorazaDirectives runs the plugin and pulls the `directives`
// string out of the single emitted handler. Returns the raw handler
// map too so tests can assert on the surrounding fields.
func extractCorazaDirectives(t *testing.T, annotations map[string]string) (handler map[string]any, directives string) {
	t.Helper()

	input := converter.IngressMiddlewareInput{
		Ingress: &networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:   "default",
				Name:        "test",
				Annotations: annotations,
			},
		},
		Route: &caddyhttp.Route{},
	}

	route, err := CorazaPlugin{}.IngressHandler(input)
	require.NoError(t, err, "IngressHandler returned an error")
	require.Len(t, route.HandlersRaw, 1, "expected exactly one handler emitted")

	require.NoError(t, json.Unmarshal(route.HandlersRaw[0], &handler))
	d, ok := handler["directives"].(string)
	require.True(t, ok, "directives field missing or not a string")
	return handler, d
}

func TestCorazaDisabled(t *testing.T) {
	input := converter.IngressMiddlewareInput{
		Ingress: &networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"caddy.ingress.kubernetes.io/coraza-disabled": "true",
				},
			},
		},
		Route: &caddyhttp.Route{},
	}
	route, err := CorazaPlugin{}.IngressHandler(input)
	require.NoError(t, err)
	assert.Empty(t, route.HandlersRaw, "no handler should be added when disabled")
}

func TestCorazaHandlerEnvelope(t *testing.T) {
	handler, _ := extractCorazaDirectives(t, nil)
	assert.Equal(t, "waf", handler["handler"])
	assert.Equal(t, true, handler["load_owasp_crs"])
}

func TestCorazaDirectives(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		expected    string
	}{
		{
			name:        "default — no per-Ingress overrides",
			annotations: nil,
			expected:    corazaDefaultDirectives,
		},
		{
			name: "rule engine On — emitted before crs-setup so it overrides the prefix default",
			annotations: map[string]string{
				"caddy.ingress.kubernetes.io/coraza-rule-engine": "On",
			},
			expected: corazaDirectivesPrefix +
				"SecRuleEngine On\n" +
				corazaDirectivesCRSSetup +
				corazaDirectivesCRSRules,
		},
		{
			name: "rule engine Off",
			annotations: map[string]string{
				"caddy.ingress.kubernetes.io/coraza-rule-engine": "Off",
			},
			expected: corazaDirectivesPrefix +
				"SecRuleEngine Off\n" +
				corazaDirectivesCRSSetup +
				corazaDirectivesCRSRules,
		},
		{
			name: "disable rules by ID — appended after CRS rules so removals reference loaded rules",
			annotations: map[string]string{
				"caddy.ingress.kubernetes.io/coraza-disable-rules": "941100, 942100 ,920100",
			},
			expected: corazaDefaultDirectives +
				"SecRuleRemoveById 941100\n" +
				"SecRuleRemoveById 942100\n" +
				"SecRuleRemoveById 920100\n",
		},
		{
			name: "disable rules by tag",
			annotations: map[string]string{
				"caddy.ingress.kubernetes.io/coraza-disable-rules-by-tag": "attack-xss,attack-sqli",
			},
			expected: corazaDefaultDirectives +
				"SecRuleRemoveByTag attack-xss\n" +
				"SecRuleRemoveByTag attack-sqli\n",
		},
		{
			name: "paranoia level — emitted between crs-setup and owasp_crs so phase:2 rules see it",
			annotations: map[string]string{
				"caddy.ingress.kubernetes.io/coraza-paranoia-level": "3",
			},
			expected: corazaDirectivesPrefix +
				corazaDirectivesCRSSetup +
				`SecAction "id:90100,phase:1,nolog,pass,t:none,setvar:tx.paranoia_level=3,setvar:tx.blocking_paranoia_level=3"` + "\n" +
				corazaDirectivesCRSRules,
		},
		{
			name: "anomaly thresholds",
			annotations: map[string]string{
				"caddy.ingress.kubernetes.io/coraza-anomaly-threshold-inbound":  "10",
				"caddy.ingress.kubernetes.io/coraza-anomaly-threshold-outbound": "8",
			},
			expected: corazaDirectivesPrefix +
				corazaDirectivesCRSSetup +
				`SecAction "id:90110,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=10"` + "\n" +
				`SecAction "id:90111,phase:1,nolog,pass,t:none,setvar:tx.outbound_anomaly_score_threshold=8"` + "\n" +
				corazaDirectivesCRSRules,
		},
		{
			name: "blocked IPs and CIDRs",
			annotations: map[string]string{
				"caddy.ingress.kubernetes.io/coraza-blocked-ips": "10.0.0.5, 192.168.1.0/24, 2001:db8::1",
			},
			expected: corazaDefaultDirectives +
				`SecRule REMOTE_ADDR "@ipMatch 10.0.0.5,192.168.1.0/24,2001:db8::1" "id:90001,phase:1,deny,status:403,log,msg:'IP blocked by ingress annotation'"` + "\n",
		},
		{
			name: "all knobs combined — stable ordering across slots",
			annotations: map[string]string{
				"caddy.ingress.kubernetes.io/coraza-rule-engine":                "On",
				"caddy.ingress.kubernetes.io/coraza-disable-rules":              "941100",
				"caddy.ingress.kubernetes.io/coraza-disable-rules-by-tag":       "attack-xss",
				"caddy.ingress.kubernetes.io/coraza-paranoia-level":             "2",
				"caddy.ingress.kubernetes.io/coraza-anomaly-threshold-inbound":  "5",
				"caddy.ingress.kubernetes.io/coraza-anomaly-threshold-outbound": "4",
				"caddy.ingress.kubernetes.io/coraza-blocked-ips":                "10.0.0.5",
			},
			expected: corazaDirectivesPrefix +
				"SecRuleEngine On\n" +
				corazaDirectivesCRSSetup +
				`SecAction "id:90100,phase:1,nolog,pass,t:none,setvar:tx.paranoia_level=2,setvar:tx.blocking_paranoia_level=2"` + "\n" +
				`SecAction "id:90110,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=5"` + "\n" +
				`SecAction "id:90111,phase:1,nolog,pass,t:none,setvar:tx.outbound_anomaly_score_threshold=4"` + "\n" +
				corazaDirectivesCRSRules +
				"SecRuleRemoveById 941100\n" +
				"SecRuleRemoveByTag attack-xss\n" +
				`SecRule REMOTE_ADDR "@ipMatch 10.0.0.5" "id:90001,phase:1,deny,status:403,log,msg:'IP blocked by ingress annotation'"` + "\n",
		},
		{
			name: "full override wins over fine-grained annotations",
			annotations: map[string]string{
				"caddy.ingress.kubernetes.io/coraza-directives":    "SecRuleEngine On\n",
				"caddy.ingress.kubernetes.io/coraza-rule-engine":   "Off",
				"caddy.ingress.kubernetes.io/coraza-disable-rules": "941100",
			},
			expected: "SecRuleEngine On\n",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, got := extractCorazaDirectives(t, tc.annotations)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestCorazaMisconfigured(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		errContains string
	}{
		{
			name: "rule engine — invalid value",
			annotations: map[string]string{
				"caddy.ingress.kubernetes.io/coraza-rule-engine": "Maybe",
			},
			errContains: "coraza-rule-engine",
		},
		{
			name: "paranoia level — non-integer",
			annotations: map[string]string{
				"caddy.ingress.kubernetes.io/coraza-paranoia-level": "high",
			},
			errContains: "coraza-paranoia-level",
		},
		{
			name: "paranoia level — out of range",
			annotations: map[string]string{
				"caddy.ingress.kubernetes.io/coraza-paranoia-level": "5",
			},
			errContains: "coraza-paranoia-level",
		},
		{
			name: "anomaly threshold inbound — non-integer",
			annotations: map[string]string{
				"caddy.ingress.kubernetes.io/coraza-anomaly-threshold-inbound": "many",
			},
			errContains: "coraza-anomaly-threshold-inbound",
		},
		{
			name: "blocked IPs — invalid entry",
			annotations: map[string]string{
				"caddy.ingress.kubernetes.io/coraza-blocked-ips": "10.0.0.5, not-an-ip",
			},
			errContains: "coraza-blocked-ips",
		},
		{
			name: "blocked IPs — invalid CIDR",
			annotations: map[string]string{
				"caddy.ingress.kubernetes.io/coraza-blocked-ips": "10.0.0.0/40",
			},
			errContains: "coraza-blocked-ips",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := converter.IngressMiddlewareInput{
				Ingress: &networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: tc.annotations,
					},
				},
				Route: &caddyhttp.Route{},
			}
			_, err := CorazaPlugin{}.IngressHandler(input)
			require.Error(t, err)
			assert.True(t, strings.Contains(err.Error(), tc.errContains),
				"error %q should mention %q", err.Error(), tc.errContains)
		})
	}
}
