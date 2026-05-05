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

func TestDropMatchingIPConfigsVM(t *testing.T) {
	primary := func(ip string) *armnetwork.InterfaceIPConfiguration {
		return &armnetwork.InterfaceIPConfiguration{
			Name: to.Ptr("primary-cfg"),
			Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
				PrivateIPAddress: to.Ptr(ip),
				Primary:          to.Ptr(true),
			},
		}
	}
	secondary := func(name, ip string) *armnetwork.InterfaceIPConfiguration {
		return &armnetwork.InterfaceIPConfiguration{
			Name: to.Ptr(name),
			Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
				PrivateIPAddress: to.Ptr(ip),
				Primary:          to.Ptr(false),
			},
		}
	}

	t.Run("drops requested non-primary IPs only", func(t *testing.T) {
		input := []*armnetwork.InterfaceIPConfiguration{
			primary("10.0.0.1"),
			secondary("a", "10.0.0.2"),
			secondary("b", "10.0.0.3"),
			secondary("c", "10.0.0.4"),
		}
		releaseSet := map[string]struct{}{"10.0.0.2": {}, "10.0.0.4": {}}
		kept, dropped, blocked := dropMatchingIPConfigsVM(input, releaseSet)
		require.Equal(t, 2, dropped)
		require.Empty(t, blocked)
		require.Len(t, kept, 2)
		require.Equal(t, "10.0.0.1", *kept[0].Properties.PrivateIPAddress)
		require.Equal(t, "10.0.0.3", *kept[1].Properties.PrivateIPAddress)
	})

	t.Run("primary in release set is reported and retained", func(t *testing.T) {
		input := []*armnetwork.InterfaceIPConfiguration{
			primary("10.0.0.1"),
			secondary("a", "10.0.0.2"),
		}
		releaseSet := map[string]struct{}{"10.0.0.1": {}, "10.0.0.2": {}}
		kept, dropped, blocked := dropMatchingIPConfigsVM(input, releaseSet)
		require.Equal(t, []string{"10.0.0.1"}, blocked)
		require.Equal(t, 1, dropped)
		require.Len(t, kept, 1)
		require.Equal(t, "10.0.0.1", *kept[0].Properties.PrivateIPAddress)
	})

	t.Run("no overlap drops nothing", func(t *testing.T) {
		input := []*armnetwork.InterfaceIPConfiguration{
			primary("10.0.0.1"),
			secondary("a", "10.0.0.2"),
		}
		releaseSet := map[string]struct{}{"10.0.0.99": {}}
		kept, dropped, blocked := dropMatchingIPConfigsVM(input, releaseSet)
		require.Equal(t, 0, dropped)
		require.Empty(t, blocked)
		require.Len(t, kept, 2)
	})

	t.Run("nil properties retained", func(t *testing.T) {
		input := []*armnetwork.InterfaceIPConfiguration{
			{Name: to.Ptr("nilprops")},
			secondary("a", "10.0.0.2"),
		}
		releaseSet := map[string]struct{}{"10.0.0.2": {}}
		kept, dropped, blocked := dropMatchingIPConfigsVM(input, releaseSet)
		require.Equal(t, 1, dropped)
		require.Empty(t, blocked)
		require.Len(t, kept, 1)
		require.Equal(t, "nilprops", *kept[0].Name)
	})
}

func TestDropMatchingIPConfigsVMSS(t *testing.T) {
	primary := func(name string) *armcompute.VirtualMachineScaleSetIPConfiguration {
		return &armcompute.VirtualMachineScaleSetIPConfiguration{
			Name: to.Ptr(name),
			Properties: &armcompute.VirtualMachineScaleSetIPConfigurationProperties{
				Primary: to.Ptr(true),
			},
		}
	}
	secondary := func(name string) *armcompute.VirtualMachineScaleSetIPConfiguration {
		return &armcompute.VirtualMachineScaleSetIPConfiguration{
			Name: to.Ptr(name),
			Properties: &armcompute.VirtualMachineScaleSetIPConfigurationProperties{
				Primary: to.Ptr(false),
			},
		}
	}

	t.Run("drops requested non-primary names only", func(t *testing.T) {
		input := []*armcompute.VirtualMachineScaleSetIPConfiguration{
			primary("pods"),
			secondary("pod-01"),
			secondary("pod-02"),
			secondary("pod-03"),
		}
		releaseNames := map[string]struct{}{"pod-01": {}, "pod-03": {}}
		kept, dropped, blocked := dropMatchingIPConfigsVMSS(input, releaseNames)
		require.Equal(t, 2, dropped)
		require.Empty(t, blocked)
		require.Len(t, kept, 2)
		require.Equal(t, "pods", *kept[0].Name)
		require.Equal(t, "pod-02", *kept[1].Name)
	})

	t.Run("primary name in release set is reported and retained", func(t *testing.T) {
		input := []*armcompute.VirtualMachineScaleSetIPConfiguration{
			primary("pods"),
			secondary("pod-01"),
		}
		releaseNames := map[string]struct{}{"pods": {}, "pod-01": {}}
		kept, dropped, blocked := dropMatchingIPConfigsVMSS(input, releaseNames)
		require.Equal(t, []string{"pods"}, blocked)
		require.Equal(t, 1, dropped)
		require.Len(t, kept, 1)
		require.Equal(t, "pods", *kept[0].Name)
	})

	t.Run("nil name retained", func(t *testing.T) {
		input := []*armcompute.VirtualMachineScaleSetIPConfiguration{
			{},
			secondary("pod-01"),
		}
		releaseNames := map[string]struct{}{"pod-01": {}}
		kept, dropped, blocked := dropMatchingIPConfigsVMSS(input, releaseNames)
		require.Equal(t, 1, dropped)
		require.Empty(t, blocked)
		require.Len(t, kept, 1)
		require.Nil(t, kept[0].Name)
	})
}

func TestPrimaryReleaseError(t *testing.T) {
	err := &PrimaryReleaseError{InterfaceName: "pods", Items: []string{"pods", "pod-99"}}
	require.Contains(t, err.Error(), "pods")
	require.Contains(t, err.Error(), "pod-99")
}
