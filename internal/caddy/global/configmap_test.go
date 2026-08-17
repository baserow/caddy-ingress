package global

import (
	"encoding/json"
	"testing"

	"github.com/caddyserver/ingress/pkg/converter"
	"github.com/caddyserver/ingress/pkg/store"

	"github.com/stretchr/testify/require"
)

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
