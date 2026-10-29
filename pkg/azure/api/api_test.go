// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v9"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	apimetrics "github.com/cilium/cilium/pkg/api/metrics/mock"
	"github.com/cilium/cilium/pkg/azure/types"
	iputil "github.com/cilium/cilium/pkg/ip"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/mac"
)

func TestParseInterface(t *testing.T) {
	ifaceID := "/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic1"
	subnetID := "/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/subnet1"

	newIPConfig := func(ip string, primary bool) *armnetwork.InterfaceIPConfiguration {
		return &armnetwork.InterfaceIPConfiguration{
			Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
				PrivateIPAddress:  new(ip),
				Primary:           new(primary),
				ProvisioningState: new(armnetwork.ProvisioningStateSucceeded),
				Subnet:            &armnetwork.Subnet{ID: new(subnetID)},
			},
		}
	}

	newIface := func(configs ...*armnetwork.InterfaceIPConfiguration) *armnetwork.Interface {
		return &armnetwork.Interface{
			ID: new(ifaceID),
			Properties: &armnetwork.InterfacePropertiesFormat{
				IPConfigurations: configs,
			},
		}
	}

	subnetMap := ipamTypes.SubnetMap{
		subnetID: &ipamTypes.Subnet{
			ID:   subnetID,
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		},
	}

	tests := []struct {
		name             string
		iface            *armnetwork.Interface
		subnets          ipamTypes.SubnetMap
		usePrimary       bool
		expectedIP       iputil.Addr
		expectedAddrs    []iputil.Addr
		expectedSubnetID string
		expectedCIDR     iputil.Prefix
		expectedGateway  iputil.Addr
	}{
		{
			name: "primary and secondaries, usePrimary=false",
			iface: newIface(
				newIPConfig("10.0.0.4", true),
				newIPConfig("10.0.0.5", false),
				newIPConfig("10.0.0.6", false),
			),
			subnets:    subnetMap,
			usePrimary: false,
			expectedIP: iputil.AddrFrom(netip.MustParseAddr("10.0.0.4")),
			expectedAddrs: []iputil.Addr{
				iputil.AddrFrom(netip.MustParseAddr("10.0.0.5")),
				iputil.AddrFrom(netip.MustParseAddr("10.0.0.6")),
			},
			expectedSubnetID: subnetID,
			expectedCIDR:     iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.0/24")),
			expectedGateway:  iputil.AddrFrom(netip.MustParseAddr("10.0.0.1")),
		},
		{
			name: "primary and secondaries, usePrimary=true",
			iface: newIface(
				newIPConfig("10.0.0.4", true),
				newIPConfig("10.0.0.5", false),
				newIPConfig("10.0.0.6", false),
			),
			subnets:    subnetMap,
			usePrimary: true,
			expectedIP: iputil.AddrFrom(netip.MustParseAddr("10.0.0.4")),
			expectedAddrs: []iputil.Addr{
				iputil.AddrFrom(netip.MustParseAddr("10.0.0.4")),
				iputil.AddrFrom(netip.MustParseAddr("10.0.0.5")),
				iputil.AddrFrom(netip.MustParseAddr("10.0.0.6")),
			},
			expectedSubnetID: subnetID,
			expectedCIDR:     iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.0/24")),
			expectedGateway:  iputil.AddrFrom(netip.MustParseAddr("10.0.0.1")),
		},
		{
			name:             "only primary, usePrimary=false, subnet derived from primary",
			iface:            newIface(newIPConfig("10.0.0.4", true)),
			subnets:          subnetMap,
			usePrimary:       false,
			expectedIP:       iputil.AddrFrom(netip.MustParseAddr("10.0.0.4")),
			expectedAddrs:    nil,
			expectedSubnetID: subnetID,
			expectedCIDR:     iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.0/24")),
			expectedGateway:  iputil.AddrFrom(netip.MustParseAddr("10.0.0.1")),
		},
		{
			name:          "no IPConfigurations",
			iface:         newIface(),
			usePrimary:    false,
			expectedIP:    iputil.Addr{},
			expectedAddrs: nil,
		},
		{
			name: "no primary flag set on any config",
			iface: newIface(
				newIPConfig("10.0.0.5", false),
				newIPConfig("10.0.0.6", false),
			),
			subnets:    subnetMap,
			usePrimary: false,
			expectedIP: iputil.Addr{},
			expectedAddrs: []iputil.Addr{
				iputil.AddrFrom(netip.MustParseAddr("10.0.0.5")),
				iputil.AddrFrom(netip.MustParseAddr("10.0.0.6")),
			},
			expectedSubnetID: subnetID,
			expectedCIDR:     iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.0/24")),
			expectedGateway:  iputil.AddrFrom(netip.MustParseAddr("10.0.0.1")),
		},
		{
			name: "nil Primary pointer treated as non-primary",
			iface: newIface(&armnetwork.InterfaceIPConfiguration{
				Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
					PrivateIPAddress:  new("10.0.0.5"),
					Primary:           nil,
					ProvisioningState: new(armnetwork.ProvisioningStateSucceeded),
					Subnet:            &armnetwork.Subnet{ID: new(subnetID)},
				},
			}),
			subnets:          subnetMap,
			usePrimary:       false,
			expectedIP:       iputil.Addr{},
			expectedAddrs:    []iputil.Addr{iputil.AddrFrom(netip.MustParseAddr("10.0.0.5"))},
			expectedSubnetID: subnetID,
			expectedCIDR:     iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.0/24")),
			expectedGateway:  iputil.AddrFrom(netip.MustParseAddr("10.0.0.1")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, got := parseInterface(hivetest.Logger(t), tt.iface, tt.subnets, tt.usePrimary)
			require.NotNil(t, got)
			require.Equal(t, ifaceID, got.ID)
			require.Equal(t, tt.expectedIP, got.IP)
			require.Equal(t, tt.expectedSubnetID, got.Subnet.ID)
			require.Equal(t, tt.expectedCIDR, got.Subnet.CIDR)
			require.Equal(t, tt.expectedGateway, got.Gateway)

			gotAddrs := make([]iputil.Addr, 0, len(got.Addresses))
			for _, a := range got.Addresses {
				gotAddrs = append(gotAddrs, a.IP)
			}
			if tt.expectedAddrs == nil {
				require.Empty(t, gotAddrs)
			} else {
				require.Equal(t, tt.expectedAddrs, gotAddrs)
			}
		})
	}
}

func TestIPConfigCIDR(t *testing.T) {
	tests := []struct {
		name         string
		address      *string
		prefixLength *int32
		expected     netip.Prefix
		wantErr      bool
	}{
		{name: "bare address", address: new("10.0.0.5"), expected: netip.MustParsePrefix("10.0.0.5/32")},
		{name: "bare IPv6 address", address: new("2001:db8::5"), expected: netip.MustParsePrefix("2001:db8::5/128")},
		{name: "CIDR without length", address: new("10.0.0.16/28"), expected: netip.MustParsePrefix("10.0.0.16/28")},
		{name: "CIDR with matching length", address: new("10.0.0.16/28"), prefixLength: new(int32(28)), expected: netip.MustParsePrefix("10.0.0.16/28")},
		{name: "address with length", address: new("10.0.0.16"), prefixLength: new(int32(28)), expected: netip.MustParsePrefix("10.0.0.16/28")},
		{name: "host CIDR", address: new("10.0.0.5/32"), expected: netip.MustParsePrefix("10.0.0.5/32")},
		{name: "address with host length", address: new("10.0.0.5"), prefixLength: new(int32(32)), expected: netip.MustParsePrefix("10.0.0.5/32")},
		{name: "IPv6 CIDR", address: new("2001:db8::/124"), prefixLength: new(int32(124)), expected: netip.MustParsePrefix("2001:db8::/124")},
		{name: "IPv6 address with length", address: new("2001:db8::"), prefixLength: new(int32(124)), expected: netip.MustParsePrefix("2001:db8::/124")},
		{name: "negative length", address: new("10.0.0.16"), prefixLength: new(int32(-1)), wantErr: true},
		{name: "mismatched length", address: new("10.0.0.16/28"), prefixLength: new(int32(27)), wantErr: true},
		{name: "CIDR not masked", address: new("10.0.0.17/28"), wantErr: true},
		{name: "address with length not masked", address: new("10.0.0.17"), prefixLength: new(int32(28)), wantErr: true},
		{name: "length out of range", address: new("10.0.0.16"), prefixLength: new(int32(33)), wantErr: true},
		{name: "nil", wantErr: true},
		{name: "garbage", address: new("not-an-ip"), wantErr: true},
		{name: "garbage CIDR", address: new("10.0.0.0/abc"), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ipConfigCIDR(tt.address, tt.prefixLength)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expected, got)
		})
	}
}

func TestParseInterfacePrefixes(t *testing.T) {
	ifaceID := "/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic1"
	ipConfig := func(address string, primary bool, state *armnetwork.ProvisioningState) *armnetwork.InterfaceIPConfiguration {
		return &armnetwork.InterfaceIPConfiguration{
			Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
				PrivateIPAddress:  new(address),
				Primary:           new(primary),
				ProvisioningState: state,
			},
		}
	}
	succeeded := new(armnetwork.ProvisioningStateSucceeded)
	iface := &armnetwork.Interface{
		ID: new(ifaceID),
		Properties: &armnetwork.InterfacePropertiesFormat{
			IPConfigurations: []*armnetwork.InterfaceIPConfiguration{
				ipConfig("10.0.0.4", true, succeeded),
				ipConfig("10.0.0.5", false, succeeded),
				ipConfig("10.0.0.16/28", false, succeeded),
				ipConfig("10.0.0.32/28", false, new(armnetwork.ProvisioningStateFailed)),
				ipConfig("10.0.0.48/28", false, nil),
				ipConfig("10.0.0.6", false, nil),
			},
		},
	}

	_, got := parseInterface(hivetest.Logger(t), iface, nil, false)
	require.Equal(t, iputil.AddrFrom(netip.MustParseAddr("10.0.0.4")), got.IP)
	require.Equal(t, []types.AzureAddress{
		{IP: iputil.AddrFrom(netip.MustParseAddr("10.0.0.5")), State: types.StateSucceeded},
		{IP: iputil.AddrFrom(netip.MustParseAddr("10.0.0.6"))},
	}, got.Addresses)
	require.Equal(t, []types.AzurePrefix{
		{CIDR: iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.16/28")), State: types.StateSucceeded},
		{CIDR: iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.32/28")), State: "failed"},
		{CIDR: iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.48/28"))},
	}, got.Prefixes)

	primaryPrefix := &armnetwork.Interface{
		ID: new(ifaceID),
		Properties: &armnetwork.InterfacePropertiesFormat{
			IPConfigurations: []*armnetwork.InterfaceIPConfiguration{
				ipConfig("10.0.0.16/28", true, succeeded),
			},
		},
	}
	_, got = parseInterface(hivetest.Logger(t), primaryPrefix, nil, true)
	require.False(t, got.IP.IsValid())
	require.Empty(t, got.Addresses)
	require.Empty(t, got.Prefixes)
}

// newInterfaceWithMAC builds an armnetwork.Interface attached to the given VM,
// with macAddress reported by the Azure API verbatim (empty means the API
// returned no MAC, as happens while the interface is still provisioning).
func newInterfaceWithMAC(id, vmID, macAddress string) *armnetwork.Interface {
	iface := &armnetwork.Interface{
		ID:   new(id),
		Name: new(id),
		Properties: &armnetwork.InterfacePropertiesFormat{
			VirtualMachine: &armnetwork.SubResource{ID: new(vmID)},
		},
	}
	if macAddress != "" {
		iface.Properties.MacAddress = new(macAddress)
	}
	return iface
}

func TestParseInterfacesIntoInstanceMapSkipsInterfacesWithoutMAC(t *testing.T) {
	const vmID = "/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1"

	c := &Client{logger: hivetest.Logger(t)}
	instances := c.ParseInterfacesIntoInstanceMap([]*armnetwork.Interface{
		newInterfaceWithMAC("nic-ready", vmID, "AA-BB-CC-DD-EE-FF"),
		newInterfaceWithMAC("nic-provisioning", vmID, ""),
	}, nil)

	got := []string{}
	instances.ForeachInterface("", func(instanceID, interfaceID string, iface ipamTypes.Interface) error {
		got = append(got, interfaceID)
		return nil
	})
	require.Equal(t, []string{"nic-ready"}, got)
}

func TestParseInterfacesIntoInstanceSkipsInterfacesWithoutMAC(t *testing.T) {
	const vmID = "/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1"

	c := &Client{logger: hivetest.Logger(t)}
	instance := c.ParseInterfacesIntoInstance([]*armnetwork.Interface{
		newInterfaceWithMAC("nic-ready", vmID, "AA-BB-CC-DD-EE-FF"),
		newInterfaceWithMAC("nic-provisioning", vmID, ""),
	}, nil)

	require.Len(t, instance.Interfaces, 1)
	require.Contains(t, instance.Interfaces, "nic-ready")
}

func TestIsMacValid(t *testing.T) {
	tests := []struct {
		name     string
		iface    *types.AzureInterface
		expected bool
	}{
		{
			name:     "nil interface",
			iface:    nil,
			expected: false,
		},
		{
			name:     "unset MAC",
			iface:    &types.AzureInterface{Name: "nic1", ID: "/nic1"},
			expected: false,
		},
		{
			name:     "valid MAC",
			iface:    &types.AzureInterface{Name: "nic1", ID: "/nic1", MAC: mac.MustParseMAC("aa:bb:cc:dd:ee:ff")},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, isMacValid(hivetest.Logger(t), tt.iface))
		})
	}
}

func TestAvailableIPs(t *testing.T) {
	cidr := netip.MustParsePrefix("10.0.0.0/8")
	require.Equal(t, 16777216, availableIPs(cidr))
	cidr = netip.MustParsePrefix("1.1.1.1/32")
	require.Equal(t, 1, availableIPs(cidr))
}

func TestFindPublicIPPrefixByTags(t *testing.T) {
	prefixes := []*armnetwork.PublicIPPrefix{
		{
			ID: new("prefix1"),
			Tags: map[string]*string{
				"env":  new("prod"),
				"pool": new("pool-1"),
			},
			Properties: &armnetwork.PublicIPPrefixPropertiesFormat{
				ProvisioningState: new(armnetwork.ProvisioningStateSucceeded),
				IPPrefix:          new("10.0.0.0/28"),
				PublicIPAddresses: []*armnetwork.ReferencedPublicIPAddress{
					{ID: new("ip1")},
				},
			},
		},
		{
			ID: new("prefix2"),
			Tags: map[string]*string{
				"env": new("dev"),
			},
			Properties: &armnetwork.PublicIPPrefixPropertiesFormat{
				ProvisioningState: new(armnetwork.ProvisioningStateSucceeded),
				IPPrefix:          new("10.1.0.0/28"),
			},
		},
		{
			// Not provisioned
			ID: new("prefix3"),
			Tags: map[string]*string{
				"env": new("staging"),
			},
			Properties: &armnetwork.PublicIPPrefixPropertiesFormat{
				ProvisioningState: new(armnetwork.ProvisioningStateFailed),
				IPPrefix:          new("10.2.0.0/28"),
			},
		},
		{
			// Full
			ID: new("prefix4"),
			Tags: map[string]*string{
				"env": new("test"),
			},
			Properties: &armnetwork.PublicIPPrefixPropertiesFormat{
				ProvisioningState: new(armnetwork.ProvisioningStateSucceeded),
				IPPrefix:          new("10.3.0.0/31"), // 2 IPs
				PublicIPAddresses: []*armnetwork.ReferencedPublicIPAddress{
					{ID: new("ip1")},
					{ID: new("ip2")},
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
					Code: new("ProvisioningState/succeeded"),
				},
			},
			expected: false,
		},
		{
			name: "failure",
			instanceViewStatuses: []*armcompute.InstanceViewStatus{
				{
					Code: new("ProvisioningState/failed/PublicIpPrefixOutOfIpAddressesForVMScaleSet"),
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

func TestRemoveInterfaceIPConfigurations(t *testing.T) {
	ipConfig := func(name, address string, primary bool) *armnetwork.InterfaceIPConfiguration {
		return &armnetwork.InterfaceIPConfiguration{
			Name: new(name),
			Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
				PrivateIPAddress: new(address),
				Primary:          new(primary),
			},
		}
	}
	primary := ipConfig("primary", "10.0.0.4", true)
	second := ipConfig("second", "10.0.0.5", false)
	third := ipConfig("third", "10.0.0.6", false)
	noName := &armnetwork.InterfaceIPConfiguration{
		Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{PrivateIPAddress: new("10.0.0.7")},
	}
	noProperties := &armnetwork.InterfaceIPConfiguration{Name: new("no-properties")}
	noAddress := &armnetwork.InterfaceIPConfiguration{
		Name:       new("no-address"),
		Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{},
	}

	tests := []struct {
		name        string
		configs     []*armnetwork.InterfaceIPConfiguration
		addresses   []string
		wantKept    []*armnetwork.InterfaceIPConfiguration
		wantRemoved []string
		wantErr     bool
	}{
		{
			name:        "match by address",
			configs:     []*armnetwork.InterfaceIPConfiguration{primary, second, third},
			addresses:   []string{"10.0.0.5"},
			wantKept:    []*armnetwork.InterfaceIPConfiguration{primary, third},
			wantRemoved: []string{"second"},
		},
		{
			name:        "absent address skipped",
			configs:     []*armnetwork.InterfaceIPConfiguration{primary, second, third},
			addresses:   []string{"10.0.0.6", "10.0.0.99"},
			wantKept:    []*armnetwork.InterfaceIPConfiguration{primary, second},
			wantRemoved: []string{"third"},
		},
		{
			name:      "nothing to remove",
			configs:   []*armnetwork.InterfaceIPConfiguration{primary, second},
			addresses: []string{"10.0.0.99"},
			wantKept:  []*armnetwork.InterfaceIPConfiguration{primary, second},
		},
		{
			name:      "primary match errors",
			configs:   []*armnetwork.InterfaceIPConfiguration{primary, second},
			addresses: []string{"10.0.0.4", "10.0.0.5"},
			wantErr:   true,
		},
		{
			name:      "nil name on match errors",
			configs:   []*armnetwork.InterfaceIPConfiguration{primary, noName},
			addresses: []string{"10.0.0.7"},
			wantErr:   true,
		},
		{
			name:        "nil entry, properties and address kept",
			configs:     []*armnetwork.InterfaceIPConfiguration{nil, noProperties, noAddress, second},
			addresses:   []string{"10.0.0.5"},
			wantKept:    []*armnetwork.InterfaceIPConfiguration{nil, noProperties, noAddress},
			wantRemoved: []string{"second"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			addresses := make([]netip.Addr, 0, len(test.addresses))
			for _, a := range test.addresses {
				addresses = append(addresses, netip.MustParseAddr(a))
			}
			kept, removed, err := removeInterfaceIPConfigurations(test.configs, addresses)
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.wantKept, kept)
			require.Equal(t, test.wantRemoved, removed)
		})
	}
}

func TestRemoveVMSSIPConfigurations(t *testing.T) {
	ipConfig := func(name string, primary bool) *armcompute.VirtualMachineScaleSetIPConfiguration {
		return &armcompute.VirtualMachineScaleSetIPConfiguration{
			Name:       new(name),
			Properties: &armcompute.VirtualMachineScaleSetIPConfigurationProperties{Primary: new(primary)},
		}
	}
	primary := ipConfig("primary", true)
	second := ipConfig("second", false)
	third := ipConfig("third", false)
	noName := &armcompute.VirtualMachineScaleSetIPConfiguration{}

	tests := []struct {
		name     string
		configs  []*armcompute.VirtualMachineScaleSetIPConfiguration
		names    []string
		wantKept []*armcompute.VirtualMachineScaleSetIPConfiguration
		wantErr  bool
	}{
		{
			name:     "drop by name",
			configs:  []*armcompute.VirtualMachineScaleSetIPConfiguration{primary, second, third},
			names:    []string{"second", "third"},
			wantKept: []*armcompute.VirtualMachineScaleSetIPConfiguration{primary},
		},
		{
			name:    "missing name errors",
			configs: []*armcompute.VirtualMachineScaleSetIPConfiguration{primary, second},
			names:   []string{"second", "third"},
			wantErr: true,
		},
		{
			name:    "primary errors",
			configs: []*armcompute.VirtualMachineScaleSetIPConfiguration{primary, second},
			names:   []string{"primary"},
			wantErr: true,
		},
		{
			name:     "nil entries kept",
			configs:  []*armcompute.VirtualMachineScaleSetIPConfiguration{nil, noName, second},
			names:    []string{"second"},
			wantKept: []*armcompute.VirtualMachineScaleSetIPConfiguration{nil, noName},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			kept, err := removeVMSSIPConfigurations(test.configs, test.names)
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.wantKept, kept)
		})
	}
}

func vmssIPConfig(name string, primary *bool) *armcompute.VirtualMachineScaleSetIPConfiguration {
	return &armcompute.VirtualMachineScaleSetIPConfiguration{
		Name:       new(name),
		Properties: &armcompute.VirtualMachineScaleSetIPConfigurationProperties{Primary: primary},
	}
}

func vmssNetworkConfig(name string, ipConfigs ...*armcompute.VirtualMachineScaleSetIPConfiguration) *armcompute.VirtualMachineScaleSetNetworkConfiguration {
	return &armcompute.VirtualMachineScaleSetNetworkConfiguration{
		Name:       new(name),
		Properties: &armcompute.VirtualMachineScaleSetNetworkConfigurationProperties{IPConfigurations: ipConfigs},
	}
}

func ipConfigNames(config *armcompute.VirtualMachineScaleSetNetworkConfiguration) []string {
	names := make([]string, 0, len(config.Properties.IPConfigurations))
	for _, ipConfig := range config.Properties.IPConfigurations {
		names = append(names, *ipConfig.Name)
	}
	return names
}

func TestPruneIPConfigurations(t *testing.T) {
	tests := []struct {
		name        string
		configs     []*armcompute.VirtualMachineScaleSetNetworkConfiguration
		applied     map[string][]string
		wantNames   [][]string
		wantDropped []string
	}{
		{
			name: "unapplied dropped",
			configs: []*armcompute.VirtualMachineScaleSetNetworkConfiguration{
				vmssNetworkConfig("nic0", vmssIPConfig("primary", new(true)), vmssIPConfig("keep", nil), vmssIPConfig("stale28", nil), vmssIPConfig("stale32a", new(false)), vmssIPConfig("stale32b", nil)),
			},
			applied:     map[string][]string{"nic0": {"primary", "keep"}},
			wantNames:   [][]string{{"primary", "keep"}},
			wantDropped: []string{"stale28", "stale32a", "stale32b"},
		},
		{
			name: "primary kept when missing from the NIC",
			configs: []*armcompute.VirtualMachineScaleSetNetworkConfiguration{
				vmssNetworkConfig("nic0", vmssIPConfig("primary", new(true)), vmssIPConfig("stale", nil)),
			},
			applied:     map[string][]string{"nic0": {}},
			wantNames:   [][]string{{"primary"}},
			wantDropped: []string{"stale"},
		},
		{
			name: "names match case-insensitively",
			configs: []*armcompute.VirtualMachineScaleSetNetworkConfiguration{
				vmssNetworkConfig("Nic0", vmssIPConfig("primary", new(true)), vmssIPConfig("keep", nil), vmssIPConfig("stale", nil)),
			},
			applied:     map[string][]string{"nic0": {"PRIMARY", "KEEP"}},
			wantNames:   [][]string{{"primary", "keep"}},
			wantDropped: []string{"stale"},
		},
		{
			name: "configuration without a NIC unchanged",
			configs: []*armcompute.VirtualMachineScaleSetNetworkConfiguration{
				vmssNetworkConfig("nic1", vmssIPConfig("primary", new(true)), vmssIPConfig("other", nil)),
			},
			applied:   map[string][]string{"nic0": {"primary"}},
			wantNames: [][]string{{"primary", "other"}},
		},
		{
			name: "configurations pruned independently",
			configs: []*armcompute.VirtualMachineScaleSetNetworkConfiguration{
				vmssNetworkConfig("nic0", vmssIPConfig("primary", new(true)), vmssIPConfig("a", nil), vmssIPConfig("b", nil)),
				vmssNetworkConfig("nic1", vmssIPConfig("primary1", new(true)), vmssIPConfig("a", nil), vmssIPConfig("b", nil)),
			},
			applied:     map[string][]string{"nic0": {"primary", "a"}, "nic1": {"primary1", "b"}},
			wantNames:   [][]string{{"primary", "a"}, {"primary1", "b"}},
			wantDropped: []string{"b", "a"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dropped := pruneIPConfigurations(test.configs, test.applied)
			require.Equal(t, test.wantDropped, dropped)
			for i, config := range test.configs {
				require.Equal(t, test.wantNames[i], ipConfigNames(config))
			}
		})
	}
}

func TestInstanceFailed(t *testing.T) {
	vm := func(state *string) *armcompute.VirtualMachineScaleSetVM {
		return &armcompute.VirtualMachineScaleSetVM{Properties: &armcompute.VirtualMachineScaleSetVMProperties{ProvisioningState: state}}
	}
	require.True(t, instanceFailed(vm(new("Failed"))))
	require.True(t, instanceFailed(vm(new("failed"))))
	require.False(t, instanceFailed(vm(new("Succeeded"))))
	require.False(t, instanceFailed(vm(nil)))
	require.False(t, instanceFailed(&armcompute.VirtualMachineScaleSetVM{}))
	require.False(t, instanceFailed(nil))
}

func TestMarkSolePrimary(t *testing.T) {
	sole := vmssNetworkConfig("nic0", vmssIPConfig("only", nil))
	markSolePrimary(sole)
	require.Equal(t, new(true), sole.Properties.IPConfigurations[0].Properties.Primary)

	soleFalse := vmssNetworkConfig("nic0", vmssIPConfig("only", new(false)))
	markSolePrimary(soleFalse)
	require.Equal(t, new(false), soleFalse.Properties.IPConfigurations[0].Properties.Primary)

	two := vmssNetworkConfig("nic0", vmssIPConfig("a", nil), vmssIPConfig("b", nil))
	markSolePrimary(two)
	require.Nil(t, two.Properties.IPConfigurations[0].Properties.Primary)
	require.Nil(t, two.Properties.IPConfigurations[1].Properties.Primary)
}

type fakeCredential struct{}

func (fakeCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

// fakeARM serves a single VMSS instance and records the models it receives.
type fakeARM struct {
	vm        string
	nics      string
	prefixes  string
	publicIPs string
	puts      []armcompute.VirtualMachineScaleSetVM
	nicLists  int
}

func (f *fakeARM) Do(req *http.Request) (*http.Response, error) {
	path := strings.ToLower(req.URL.Path)
	body := ""
	switch {
	case req.Method == http.MethodPut && strings.HasSuffix(path, "/virtualmachines/0"):
		raw, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		var vm armcompute.VirtualMachineScaleSetVM
		if err := json.Unmarshal(raw, &vm); err != nil {
			return nil, err
		}
		f.puts = append(f.puts, vm)
		body = `{"properties":{"provisioningState":"Succeeded"}}`
	case strings.HasSuffix(path, "/publicipaddresses"):
		body = f.publicIPs
	case strings.HasSuffix(path, "/networkinterfaces"):
		if req.Method != http.MethodGet || path != "/subscriptions/sub/resourcegroups/rg/providers/microsoft.compute/virtualmachinescalesets/vmss/virtualmachines/0/networkinterfaces" {
			return nil, fmt.Errorf("unexpected interface list request %s %s", req.Method, req.URL.Path)
		}
		f.nicLists++
		body = f.nics
	case strings.HasSuffix(path, "/publicipprefixes"):
		body = f.prefixes
	case strings.HasSuffix(path, "/virtualmachines/0"):
		body = f.vm
	default:
		return &http.Response{StatusCode: http.StatusNotFound, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{}`)), Request: req}, nil
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}, nil
}

func newFakeARMClient(t *testing.T, transport *fakeARM) *Client {
	t.Helper()
	c, err := newClient(hivetest.Logger(t), "sub", "rg", fakeCredential{}, &arm.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Cloud:     cloud.AzurePublic,
			Transport: transport,
			Retry:     policy.RetryOptions{MaxRetries: -1},
		},
	}, apimetrics.NewMockMetrics(), 1000, 100, false)
	require.NoError(t, err)
	return c
}

func modelIPConfigNames(t *testing.T, vm armcompute.VirtualMachineScaleSetVM) map[string]*armcompute.VirtualMachineScaleSetIPConfiguration {
	t.Helper()
	require.NotNil(t, vm.Properties)
	require.NotNil(t, vm.Properties.NetworkProfileConfiguration)
	configs := vm.Properties.NetworkProfileConfiguration.NetworkInterfaceConfigurations
	require.Len(t, configs, 1)
	names := map[string]*armcompute.VirtualMachineScaleSetIPConfiguration{}
	for _, ipConfig := range configs[0].Properties.IPConfigurations {
		names[*ipConfig.Name] = ipConfig
	}
	return names
}

const failedVMSSInstance = `{
  "location": "westus2",
  "properties": {
    "provisioningState": "Failed",
    "storageProfile": {"imageReference": {"id": "image"}},
    "networkProfileConfiguration": {"networkInterfaceConfigurations": [{
      "name": "nic0",
      "properties": {"primary": true, "ipConfigurations": [
        {"name": "primary", "properties": {"primary": true, "subnet": {"id": "subnet"}%s}},
        {"name": "keep", "properties": {"subnet": {"id": "subnet"}}},
        {"name": "release", "properties": {"subnet": {"id": "subnet"}}},
        {"name": "stale", "properties": {"privateIPAddressPrefixLength": 28, "subnet": {"id": "subnet"}}}
      ]}
    }]}%s
  }
}`

const failedVMSSInstanceNICs = `{"value": [{
  "name": "nic0",
  "properties": {"primary": true, "ipConfigurations": [
    {"name": "primary", "properties": {"primary": true, "privateIPAddress": "10.0.0.4", "provisioningState": "Succeeded"}},
    {"name": "KEEP", "properties": {"privateIPAddress": "10.0.0.5", "provisioningState": "Succeeded"}},
    {"name": "release", "properties": {"privateIPAddress": "10.0.0.6", "provisioningState": "Succeeded"}}
  ]}
}]}`

func TestAssignPrivateIpAddressesVMSSDropsUnappliedIPConfigurations(t *testing.T) {
	transport := &fakeARM{vm: fmt.Sprintf(failedVMSSInstance, "", ""), nics: failedVMSSInstanceNICs}
	c := newFakeARMClient(t, transport)

	require.NoError(t, c.AssignPrivateIpAddressesVMSS(t.Context(), "0", "vmss", "subnet", "nic0", 1))

	require.Len(t, transport.puts, 1)
	require.Equal(t, 1, transport.nicLists)
	names := modelIPConfigNames(t, transport.puts[0])
	require.Len(t, names, 4)
	require.Contains(t, names, "primary")
	require.Equal(t, new(true), names["primary"].Properties.Primary)
	require.Contains(t, names, "keep")
	require.Contains(t, names, "release")
	require.NotContains(t, names, "stale")
}

func TestAssignPrivateIpAddressesVMSSMarksSolePrimary(t *testing.T) {
	transport := &fakeARM{vm: `{
  "location": "westus2",
  "properties": {
    "provisioningState": "Succeeded",
    "networkProfileConfiguration": {"networkInterfaceConfigurations": [{
      "name": "nic0",
      "properties": {"ipConfigurations": [{"name": "only", "properties": {"subnet": {"id": "subnet"}}}]}
    }]}
  }
}`}
	c := newFakeARMClient(t, transport)

	require.NoError(t, c.AssignPrivateIpAddressesVMSS(t.Context(), "0", "vmss", "subnet", "nic0", 2))

	require.Len(t, transport.puts, 1)
	require.Equal(t, 0, transport.nicLists)
	names := modelIPConfigNames(t, transport.puts[0])
	require.Len(t, names, 3)
	require.Equal(t, new(true), names["only"].Properties.Primary)
}

func TestUnassignPrivateIpAddressesVMSSDropsUnappliedIPConfigurations(t *testing.T) {
	transport := &fakeARM{vm: fmt.Sprintf(failedVMSSInstance, "", ""), nics: failedVMSSInstanceNICs}
	c := newFakeARMClient(t, transport)

	require.NoError(t, c.UnassignPrivateIpAddressesVMSS(t.Context(), "0", "vmss", "nic0", []netip.Addr{netip.MustParseAddr("10.0.0.6")}))

	require.Len(t, transport.puts, 1)
	names := modelIPConfigNames(t, transport.puts[0])
	require.Len(t, names, 2)
	require.Equal(t, new(true), names["primary"].Properties.Primary)
	require.Contains(t, names, "keep")
	require.NotContains(t, names, "release")
	require.NotContains(t, names, "stale")
}

func TestAssignPublicIPAddressesVMSSDropsUnappliedIPConfigurations(t *testing.T) {
	transport := &fakeARM{
		vm: fmt.Sprintf(failedVMSSInstance,
			`, "publicIPAddressConfiguration": {"name": "old", "properties": {}}`,
			`, "instanceView": {"statuses": [{"code": "ProvisioningState/failed/PublicIpPrefixOutOfIpAddressesForVMScaleSet"}]}`),
		nics:      failedVMSSInstanceNICs,
		prefixes:  `{"value": [{"id": "prefix", "tags": {"k": "v"}, "properties": {"provisioningState": "Succeeded", "ipPrefix": "20.0.0.0/28"}}]}`,
		publicIPs: `{"value": [{"properties": {"ipAddress": "20.0.0.5"}}]}`,
	}
	c := newFakeARMClient(t, transport)

	addr, err := c.AssignPublicIPAddressesVMSS(t.Context(),
		"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/vmss/virtualMachines/0",
		"vmss", ipamTypes.Tags{"k": "v"})
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("20.0.0.5"), addr)

	require.Len(t, transport.puts, 2)
	for i, put := range transport.puts {
		names := modelIPConfigNames(t, put)
		require.Len(t, names, 3, "PUT %d", i)
		require.Equal(t, new(true), names["primary"].Properties.Primary, "PUT %d", i)
		require.Contains(t, names, "keep", "PUT %d", i)
		require.Contains(t, names, "release", "PUT %d", i)
		require.NotContains(t, names, "stale", "PUT %d", i)
	}
	require.Nil(t, modelIPConfigNames(t, transport.puts[0])["primary"].Properties.PublicIPAddressConfiguration)
	require.NotNil(t, modelIPConfigNames(t, transport.puts[1])["primary"].Properties.PublicIPAddressConfiguration)
}
