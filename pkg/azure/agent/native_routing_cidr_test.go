// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	azureTypes "github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/cidr"
	iputil "github.com/cilium/cilium/pkg/ip"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

func TestDeriveSubnetCIDR(t *testing.T) {
	node := &ciliumv2.CiliumNode{}
	require.False(t, deriveSubnetCIDR(node).IsValid())

	node.Status.Azure.Interfaces = []azureTypes.AzureInterface{
		{},
		{
			Subnet: azureTypes.AzureSubnet{
				CIDR: iputil.PrefixFrom(netip.MustParsePrefix("2001:db8::/64")),
			},
		},
		{
			Subnet: azureTypes.AzureSubnet{
				CIDR: iputil.PrefixFrom(netip.MustParsePrefix("10.10.1.4/24")),
			},
		},
		{
			Subnet: azureTypes.AzureSubnet{
				CIDR: iputil.PrefixFrom(netip.MustParsePrefix("10.20.0.0/16")),
			},
		},
	}
	require.Equal(t, netip.MustParsePrefix("10.10.1.0/24"), deriveSubnetCIDR(node))

	node.Status.Azure.Interfaces = []azureTypes.AzureInterface{
		{CIDR: iputil.PrefixFrom(netip.MustParsePrefix("10.30.1.4/24"))}, //nolint:staticcheck // older operator status
	}
	require.Equal(t, netip.MustParsePrefix("10.30.1.0/24"), deriveSubnetCIDR(node))
}

func TestAutoDetectNativeRoutingCIDR(t *testing.T) {
	subnetCIDR := netip.MustParsePrefix("10.10.0.0/16")

	for _, tt := range []struct {
		name       string
		nativeCIDR *cidr.CIDR
		wantError  bool
	}{
		{
			name:       "configured subnet",
			nativeCIDR: cidr.MustParseCIDR("10.10.64.0/19"),
		},
		{
			name:       "configured supernet",
			nativeCIDR: cidr.MustParseCIDR("10.0.0.0/8"),
		},
		{
			name:       "disjoint configuration",
			nativeCIDR: cidr.MustParseCIDR("192.168.0.0/16"),
			wantError:  true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
			conf := &option.DaemonConfig{IPv4NativeRoutingCIDR: tt.nativeCIDR}
			err := autoDetectNativeRoutingCIDR(hivetest.Logger(t), subnetCIDR, localNodeStore, conf)
			if tt.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			localNode, err := localNodeStore.Get(t.Context())
			require.NoError(t, err)
			require.Nil(t, localNode.Local.IPv4NativeRoutingCIDR)
		})
	}

	t.Run("autodetected subnet", func(t *testing.T) {
		localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
		require.NoError(t, autoDetectNativeRoutingCIDR(
			hivetest.Logger(t),
			subnetCIDR,
			localNodeStore,
			&option.DaemonConfig{},
		))

		localNode, err := localNodeStore.Get(t.Context())
		require.NoError(t, err)
		require.Equal(t, subnetCIDR.String(), localNode.Local.IPv4NativeRoutingCIDR.String())
	})
}
