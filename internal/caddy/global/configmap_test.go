package global

import (
	"encoding/json"
	"testing"

	"github.com/caddyserver/ingress/pkg/converter"
	"github.com/caddyserver/ingress/pkg/store"

	"github.com/stretchr/testify/require"
)

func TestConfigMapTrustedProxies(t *testing.T) {
	testCases := []struct {
		desc              string
		configMap         store.ConfigMapOptions
		expectedRaw       string
		expectedIPHeaders []string
	}{
		{
			desc:      "unset leaves trusted proxies and client IP headers empty",
			configMap: store.ConfigMapOptions{},
		},
		{
			desc: "trusted proxies render a static ip_source with client IP headers",
			configMap: store.ConfigMapOptions{
				TrustedProxies:  []string{"173.245.48.0/20", "2400:cb00::/32"},
				ClientIPHeaders: []string{"CF-Connecting-IP", "X-Forwarded-For"},
			},
			expectedRaw:       `{"source":"static","ranges":["173.245.48.0/20","2400:cb00::/32"]}`,
			expectedIPHeaders: []string{"CF-Connecting-IP", "X-Forwarded-For"},
		},
		{
			desc: "client IP headers alone are ignored without trusted proxies",
			configMap: store.ConfigMapOptions{
				ClientIPHeaders: []string{"CF-Connecting-IP"},
			},
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			cfg := converter.NewConfig()
			s := store.NewStore(store.Options{}, "", &store.PodInfo{})
			s.ConfigMap = &tC.configMap

			err := ConfigMapPlugin{}.GlobalHandler(cfg, s)
			require.NoError(t, err)

			srv := cfg.GetHTTPServer()
			if tC.expectedRaw == "" {
				require.Nil(t, srv.TrustedProxiesRaw)
				require.Nil(t, srv.ClientIPHeaders)
			} else {
				require.JSONEq(t, tC.expectedRaw, string(srv.TrustedProxiesRaw))
				require.Equal(t, tC.expectedIPHeaders, srv.ClientIPHeaders)
			}
		})
	}
}

func TestConfigMapProxyProtocolListenerWrappers(t *testing.T) {
	testCases := []struct {
		desc             string
		configMap        store.ConfigMapOptions
		expectedWrappers []string
	}{
		{
			desc:             "proxy protocol disabled leaves wrappers unset",
			configMap:        store.ConfigMapOptions{},
			expectedWrappers: nil,
		},
		{
			desc:      "proxy protocol without allow list",
			configMap: store.ConfigMapOptions{ProxyProtocol: true},
			expectedWrappers: []string{
				`{"wrapper":"proxy_protocol"}`,
				`{"wrapper":"tls"}`,
			},
		},
		{
			desc: "proxy protocol with allow list",
			configMap: store.ConfigMapOptions{
				ProxyProtocol:      true,
				ProxyProtocolAllow: []string{"10.0.64.128/25", "10.0.65.0/25"},
			},
			expectedWrappers: []string{
				`{"allow":["10.0.64.128/25","10.0.65.0/25"],"wrapper":"proxy_protocol"}`,
				`{"wrapper":"tls"}`,
			},
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			cfg := converter.NewConfig()
			s := store.NewStore(store.Options{}, "", &store.PodInfo{})
			s.ConfigMap = &tC.configMap

			err := ConfigMapPlugin{}.GlobalHandler(cfg, s)
			require.NoError(t, err)

			wrappers := cfg.GetHTTPServer().ListenerWrappersRaw
			require.Len(t, wrappers, len(tC.expectedWrappers))
			for i, expected := range tC.expectedWrappers {
				require.JSONEq(t, expected, string(json.RawMessage(wrappers[i])))
			}
		})
	}
}
