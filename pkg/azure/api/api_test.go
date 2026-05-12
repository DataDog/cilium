// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"net/netip"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v7"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v8"
	"github.com/stretchr/testify/require"

	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
)

func TestAvailableIPs(t *testing.T) {
	cidr := netip.MustParsePrefix("10.0.0.0/8")
	require.Equal(t, 16777216, availableIPs(cidr))
	cidr = netip.MustParsePrefix("1.1.1.1/32")
	require.Equal(t, 1, availableIPs(cidr))
}

func TestFindPublicIPPrefixByTags(t *testing.T) {
	prefixes := []*armnetwork.PublicIPPrefix{
		{
			ID: to.Ptr("prefix1"),
			Tags: map[string]*string{
				"env":  to.Ptr("prod"),
				"pool": to.Ptr("pool-1"),
			},
			Properties: &armnetwork.PublicIPPrefixPropertiesFormat{
				ProvisioningState: to.Ptr(armnetwork.ProvisioningStateSucceeded),
				IPPrefix:          to.Ptr("10.0.0.0/28"),
				PublicIPAddresses: []*armnetwork.ReferencedPublicIPAddress{
					{ID: to.Ptr("ip1")},
				},
			},
		},
		{
			ID: to.Ptr("prefix2"),
			Tags: map[string]*string{
				"env": to.Ptr("dev"),
			},
			Properties: &armnetwork.PublicIPPrefixPropertiesFormat{
				ProvisioningState: to.Ptr(armnetwork.ProvisioningStateSucceeded),
				IPPrefix:          to.Ptr("10.1.0.0/28"),
			},
		},
		{
			// Not provisioned
			ID: to.Ptr("prefix3"),
			Tags: map[string]*string{
				"env": to.Ptr("staging"),
			},
			Properties: &armnetwork.PublicIPPrefixPropertiesFormat{
				ProvisioningState: to.Ptr(armnetwork.ProvisioningStateFailed),
				IPPrefix:          to.Ptr("10.2.0.0/28"),
			},
		},
		{
			// Full
			ID: to.Ptr("prefix4"),
			Tags: map[string]*string{
				"env": to.Ptr("test"),
			},
			Properties: &armnetwork.PublicIPPrefixPropertiesFormat{
				ProvisioningState: to.Ptr(armnetwork.ProvisioningStateSucceeded),
				IPPrefix:          to.Ptr("10.3.0.0/31"), // 2 IPs
				PublicIPAddresses: []*armnetwork.ReferencedPublicIPAddress{
					{ID: to.Ptr("ip1")},
					{ID: to.Ptr("ip2")},
				},
			},
		},
	}

	// Test exact tag match
	prefixID, found := findPublicIPPrefixByTags(prefixes, ipamTypes.Tags{
		"env":  "prod",
		"pool": "pool-1",
	})
	require.True(t, found)
	require.Equal(t, "prefix1", prefixID)

	// Test subset tag match
	prefixID, found = findPublicIPPrefixByTags(prefixes, ipamTypes.Tags{
		"env": "dev",
	})
	require.True(t, found)
	require.Equal(t, "prefix2", prefixID)

	// Test no match for non-existent tags
	_, found = findPublicIPPrefixByTags(prefixes, ipamTypes.Tags{
		"env": "nonexistent",
	})
	require.False(t, found)

	// Test skipping non-provisioned prefix
	_, found = findPublicIPPrefixByTags(prefixes, ipamTypes.Tags{
		"env": "staging",
	})
	require.False(t, found)

	// Test skipping full prefix
	_, found = findPublicIPPrefixByTags(prefixes, ipamTypes.Tags{
		"env": "test",
	})
	require.False(t, found)
}

func TestIsPublicIPProvisionFailed(t *testing.T) {
	tests := []struct {
		name                 string
		instanceViewStatuses []*armcompute.InstanceViewStatus
		expected             bool
	}{
		{
			name: "success",
			instanceViewStatuses: []*armcompute.InstanceViewStatus{
				{
					Code: to.Ptr("ProvisioningState/succeeded"),
				},
			},
			expected: false,
		},
		{
			name: "failure",
			instanceViewStatuses: []*armcompute.InstanceViewStatus{
				{
					Code: to.Ptr("ProvisioningState/failed/PublicIpPrefixOutOfIpAddressesForVMScaleSet"),
				},
			},
			expected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.expected, isPublicIPProvisionFailed(test.instanceViewStatuses))
		})
	}
}

func TestParseSubnetID(t *testing.T) {
	tests := []struct {
		name           string
		subnetID       string
		expectedRG     string
		expectedVNet   string
		expectedSubnet string
		expectError    bool
	}{
		{
			name:           "valid subnet ID",
			subnetID:       "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVNet/subnets/mySubnet",
			expectedRG:     "myResourceGroup",
			expectedVNet:   "myVNet",
			expectedSubnet: "mySubnet",
			expectError:    false,
		},
		{
			name:           "valid subnet ID with different names",
			subnetID:       "/subscriptions/87654321-4321-4321-4321-cba987654321/resourceGroups/test-rg-2/providers/Microsoft.Network/virtualNetworks/prod-vnet/subnets/app-subnet",
			expectedRG:     "test-rg-2",
			expectedVNet:   "prod-vnet",
			expectedSubnet: "app-subnet",
			expectError:    false,
		},
		{
			name:        "invalid format - missing subscription",
			subnetID:    "/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVNet/subnets/mySubnet",
			expectError: true,
		},
		{
			name:        "invalid format - missing resource group",
			subnetID:    "/subscriptions/12345678-1234-1234-1234-123456789abc/providers/Microsoft.Network/virtualNetworks/myVNet/subnets/mySubnet",
			expectError: true,
		},
		{
			name:        "invalid format - missing virtual network",
			subnetID:    "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/myResourceGroup/providers/Microsoft.Network/subnets/mySubnet",
			expectError: true,
		},
		{
			name:        "invalid format - missing subnet",
			subnetID:    "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVNet",
			expectError: true,
		},
		{
			name:        "empty subnet ID",
			subnetID:    "",
			expectError: true,
		},
		{
			name:        "invalid provider namespace",
			subnetID:    "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualNetworks/myVNet/subnets/mySubnet",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rg, vnet, subnet, err := parseSubnetID(tt.subnetID)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if rg != tt.expectedRG {
				t.Errorf("expected resource group %q, got %q", tt.expectedRG, rg)
			}

			if vnet != tt.expectedVNet {
				t.Errorf("expected virtual network %q, got %q", tt.expectedVNet, vnet)
			}

			if subnet != tt.expectedSubnet {
				t.Errorf("expected subnet %q, got %q", tt.expectedSubnet, subnet)
			}
		})
	}
}

func TestParseInterfaceWithPrefix(t *testing.T) {
	subnetID := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/default"
	subnetCIDR := netip.MustParsePrefix("10.0.0.0/24")
	subnets := ipamTypes.SubnetMap{
		subnetID: {
			ID:   subnetID,
			CIDR: subnetCIDR,
		},
	}

	iface := &armnetwork.Interface{
		ID:   to.Ptr("/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/iface0"),
		Name: to.Ptr("iface0"),
		Properties: &armnetwork.InterfacePropertiesFormat{
			MacAddress: to.Ptr("AA-BB-CC-DD-EE-FF"),
			VirtualMachine: &armnetwork.SubResource{
				ID: to.Ptr("/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm0"),
			},
			IPConfigurations: []*armnetwork.InterfaceIPConfiguration{
				{
					Name: to.Ptr("primary"),
					Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
						Primary:           to.Ptr(true),
						PrivateIPAddress:  to.Ptr("10.0.0.4"),
						ProvisioningState: to.Ptr(armnetwork.ProvisioningStateSucceeded),
						Subnet:            &armnetwork.Subnet{ID: to.Ptr(subnetID)},
					},
				},
				{
					Name: to.Ptr("prefix0"),
					Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
						Primary:                      to.Ptr(false),
						PrivateIPAddress:             to.Ptr("10.0.0.16"),
						PrivateIPAddressPrefixLength: to.Ptr(int32(28)),
						ProvisioningState:            to.Ptr(armnetwork.ProvisioningStateSucceeded),
						Subnet:                       &armnetwork.Subnet{ID: to.Ptr(subnetID)},
					},
				},
			},
		},
	}

	_, az := parseInterface(iface, subnets, false)
	require.NotNil(t, az)
	require.Equal(t, []string{"10.0.0.16/28"}, az.Prefixes)
	require.Len(t, az.Addresses, 16, "/28 should expand to 16 addresses (primary excluded since usePrimary=false)")
	for _, addr := range az.Addresses {
		require.Equal(t, subnetID, addr.Subnet)
	}
}

func TestParseInterfaceWithPrefixNormalizesHostBits(t *testing.T) {
	// Azure may return PrivateIPAddress mid-prefix; the network address should
	// be normalized so downstream comparisons are stable.
	iface := &armnetwork.Interface{
		ID:   to.Ptr("/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/iface0"),
		Name: to.Ptr("iface0"),
		Properties: &armnetwork.InterfacePropertiesFormat{
			VirtualMachine: &armnetwork.SubResource{
				ID: to.Ptr("/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm0"),
			},
			IPConfigurations: []*armnetwork.InterfaceIPConfiguration{
				{
					Name: to.Ptr("prefix0"),
					Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
						PrivateIPAddress:             to.Ptr("10.0.0.21"),
						PrivateIPAddressPrefixLength: to.Ptr(int32(28)),
						ProvisioningState:            to.Ptr(armnetwork.ProvisioningStateSucceeded),
					},
				},
			},
		},
	}

	_, az := parseInterface(iface, ipamTypes.SubnetMap{}, false)
	require.NotNil(t, az)
	require.Equal(t, []string{"10.0.0.16/28"}, az.Prefixes, "host bits should be masked")
}

func TestParseInterfaceWithPrefixCIDRInAddress(t *testing.T) {
	// Azure's NIC resource (armnetwork.InterfacesClient.Get / List) returns
	// PrivateIPAddress as a CIDR string ("10.0.0.16/28") for Prefix on NIC
	// configurations, while the VMSS VM model returns the bare address.
	// parseInterface must strip the suffix before composing the prefix.
	iface := &armnetwork.Interface{
		ID:   to.Ptr("/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/iface0"),
		Name: to.Ptr("iface0"),
		Properties: &armnetwork.InterfacePropertiesFormat{
			VirtualMachine: &armnetwork.SubResource{
				ID: to.Ptr("/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm0"),
			},
			IPConfigurations: []*armnetwork.InterfaceIPConfiguration{
				{
					Name: to.Ptr("prefix0"),
					Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
						PrivateIPAddress:             to.Ptr("10.0.0.16/28"),
						PrivateIPAddressPrefixLength: to.Ptr(int32(28)),
						ProvisioningState:            to.Ptr(armnetwork.ProvisioningStateSucceeded),
					},
				},
			},
		},
	}

	_, az := parseInterface(iface, ipamTypes.SubnetMap{}, false)
	require.NotNil(t, az)
	require.Equal(t, []string{"10.0.0.16/28"}, az.Prefixes)
	require.Len(t, az.Addresses, 16, "/28 expands to 16 addresses even when PrivateIPAddress is CIDR")
}

func TestComposePrefixCIDR(t *testing.T) {
	// VMSS VM model returns bare address.
	require.Equal(t, "10.0.0.16/28", composePrefixCIDR("10.0.0.16", 28))
	// NIC resource returns CIDR-form PrivateIPAddress; existing suffix must be
	// stripped before re-composing so the key matches the parsed Prefixes slice.
	require.Equal(t, "10.0.0.16/28", composePrefixCIDR("10.0.0.16/28", 28))
	require.Equal(t, "10.0.0.0/28", composePrefixCIDR("10.0.0.0/32", 28))
}
