package store

import (
	"testing"

	"github.com/stretchr/testify/require"
	apiv1 "k8s.io/api/core/v1"
)

func TestParseConfigMapProxyProtocolAllow(t *testing.T) {
	tests := []struct {
		name     string
		data     map[string]string
		expected []string
	}{
		{
			name:     "unset leaves allow list empty",
			data:     map[string]string{"proxyProtocol": "true"},
			expected: nil,
		},
		{
			name: "empty string yields empty allow list",
			data: map[string]string{
				"proxyProtocol":      "true",
				"proxyProtocolAllow": "",
			},
			expected: []string{},
		},
		{
			name: "single CIDR",
			data: map[string]string{
				"proxyProtocol":      "true",
				"proxyProtocolAllow": "10.0.64.128/25",
			},
			expected: []string{"10.0.64.128/25"},
		},
		{
			name: "comma-separated CIDRs",
			data: map[string]string{
				"proxyProtocol":      "true",
				"proxyProtocolAllow": "10.0.64.128/25,10.0.65.0/25",
			},
			expected: []string{"10.0.64.128/25", "10.0.65.0/25"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfgMap, err := ParseConfigMap(&apiv1.ConfigMap{Data: test.data})
			require.NoError(t, err)
			require.True(t, cfgMap.ProxyProtocol)
			require.Equal(t, test.expected, cfgMap.ProxyProtocolAllow)
		})
	}
}
