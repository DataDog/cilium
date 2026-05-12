// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mock

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/azure/types"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
)

func TestMock(t *testing.T) {
	cidr := netip.MustParsePrefix("10.0.0.0/16")
	subnet := &ipamTypes.Subnet{ID: "s-1", CIDR: cidr, AvailableAddresses: 65534}
	api := NewAPI([]*ipamTypes.Subnet{subnet}, []*ipamTypes.VirtualNetwork{{ID: "v-1"}})
	require.NotNil(t, api)

	instances, err := api.GetInstances(t.Context(), ipamTypes.SubnetMap{})
	require.NoError(t, err)
	require.Equal(t, 0, instances.NumInstances())

	vnets, subnets, err := api.GetVpcsAndSubnets(t.Context())
	require.NoError(t, err)
	require.Len(t, vnets, 1)
	require.Equal(t, &ipamTypes.VirtualNetwork{ID: "v-1"}, vnets["v-1"])
	require.Len(t, subnets, 1)
	require.Equal(t, subnet, subnets["s-1"])

	ifaceID := "/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm1/networkInterfaces/vmss11"
	instances = ipamTypes.NewInstanceMap()
	resource := &types.AzureInterface{Name: "eth0"}
	resource.SetID(ifaceID)
	instances.Update("vm1", ipamTypes.InterfaceRevision{
		Resource: resource.DeepCopy(),
	})
	api.UpdateInstances(instances)
	instances, err = api.GetInstances(t.Context(), ipamTypes.SubnetMap{})
	require.NoError(t, err)
	require.Equal(t, 1, instances.NumInstances())
	instances.ForeachInterface("", func(instanceID, interfaceID string, iface ipamTypes.InterfaceRevision) error {
		require.Equal(t, "vm1", instanceID)
		require.Equal(t, ifaceID, interfaceID)
		return nil
	})

	err = api.AssignPrivateIpAddressesVMSS(t.Context(), "vm1", "vmss1", "s-1", "eth0", 2)
	require.NoError(t, err)
	instances, err = api.GetInstances(t.Context(), ipamTypes.SubnetMap{})
	require.NoError(t, err)
	require.Equal(t, 1, instances.NumInstances())
	instances.ForeachInterface("", func(instanceID, interfaceID string, revision ipamTypes.InterfaceRevision) error {
		require.Equal(t, "vm1", instanceID)
		require.Equal(t, ifaceID, interfaceID)

		iface, ok := revision.Resource.(*types.AzureInterface)
		require.True(t, ok)
		require.Len(t, iface.Addresses, 2)
		return nil
	})

	vmIfaceID := "/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Network/networkInterfaces/vm22-if"
	vmInstances := ipamTypes.NewInstanceMap()
	resource = &types.AzureInterface{Name: "eth0"}
	resource.SetID(vmIfaceID)
	vmInstances.Update("vm2", ipamTypes.InterfaceRevision{
		Resource: resource.DeepCopy(),
	})
	require.NoError(t, err)
	require.Equal(t, 1, vmInstances.NumInstances())
	vmInstances.ForeachInterface("", func(instanceID, interfaceID string, iface ipamTypes.InterfaceRevision) error {
		require.Equal(t, "vm2", instanceID)
		require.Equal(t, vmIfaceID, interfaceID)
		return nil
	})

}

func TestSetMockError(t *testing.T) {
	api := NewAPI([]*ipamTypes.Subnet{}, []*ipamTypes.VirtualNetwork{})
	require.NotNil(t, api)

	mockError := errors.New("error")

	api.SetMockError(GetInstances, mockError)
	_, err := api.GetInstances(t.Context(), ipamTypes.SubnetMap{})
	require.ErrorIs(t, err, mockError)

	api.SetMockError(GetVpcsAndSubnets, mockError)
	_, _, err = api.GetVpcsAndSubnets(t.Context())
	require.ErrorIs(t, err, mockError)

	api.SetMockError(AssignPrivateIpAddressesVMSS, mockError)
	err = api.AssignPrivateIpAddressesVMSS(t.Context(), "vmss1", "i-1", "s-1", "eth0", 0)
	require.ErrorIs(t, err, mockError)
}

func TestMockAssignAndUnassignPrefixesVMSS(t *testing.T) {
	subnetCIDR := netip.MustParsePrefix("10.0.0.0/24")
	subnet := &ipamTypes.Subnet{ID: "s-1", CIDR: subnetCIDR, AvailableAddresses: 256}
	api := NewAPI([]*ipamTypes.Subnet{subnet}, []*ipamTypes.VirtualNetwork{{ID: "v-1"}})

	ifaceID := "/subscriptions/x/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss-pd/virtualMachines/0/networkInterfaces/eth0"
	vmID := "/subscriptions/x/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss-pd/virtualMachines/0"
	resource := &types.AzureInterface{Name: "eth0"}
	resource.SetID(ifaceID)
	instances := ipamTypes.NewInstanceMap()
	instances.Update(vmID, ipamTypes.InterfaceRevision{Resource: resource.DeepCopy()})
	api.UpdateInstances(instances)

	require.NoError(t, api.AssignPrivatePrefixesVMSS(t.Context(), "0", "vmss-pd", "s-1", "eth0", 2))

	got, err := api.GetInstances(t.Context(), ipamTypes.SubnetMap{})
	require.NoError(t, err)
	var prefixes []string
	got.ForeachInterface("", func(_, _ string, rev ipamTypes.InterfaceRevision) error {
		az, ok := rev.Resource.(*types.AzureInterface)
		require.True(t, ok)
		prefixes = append(prefixes, az.Prefixes...)
		require.Len(t, az.Prefixes, 2, "expected 2 /28 prefixes")
		require.Len(t, az.Addresses, 32, "expected 32 expanded IPs (2 x 16)")
		return nil
	})

	require.NoError(t, api.UnassignPrivatePrefixesVMSS(t.Context(), "0", "vmss-pd", "eth0", prefixes))

	got, err = api.GetInstances(t.Context(), ipamTypes.SubnetMap{})
	require.NoError(t, err)
	got.ForeachInterface("", func(_, _ string, rev ipamTypes.InterfaceRevision) error {
		az, ok := rev.Resource.(*types.AzureInterface)
		require.True(t, ok)
		require.Empty(t, az.Prefixes, "all prefixes should have been released")
		require.Empty(t, az.Addresses, "all expanded addresses should have been removed")
		return nil
	})
}

func TestMockAssignPrefixesVMSSSubnetFull(t *testing.T) {
	// /28 subnet has room for exactly one /28 block.
	subnet := &ipamTypes.Subnet{ID: "s-tiny", CIDR: netip.MustParsePrefix("10.0.0.0/28"), AvailableAddresses: 16}
	api := NewAPI([]*ipamTypes.Subnet{subnet}, []*ipamTypes.VirtualNetwork{{ID: "v-1"}})

	ifaceID := "/subscriptions/x/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss-tiny/virtualMachines/0/networkInterfaces/eth0"
	vmID := "/subscriptions/x/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss-tiny/virtualMachines/0"
	resource := &types.AzureInterface{Name: "eth0"}
	resource.SetID(ifaceID)
	instances := ipamTypes.NewInstanceMap()
	instances.Update(vmID, ipamTypes.InterfaceRevision{Resource: resource.DeepCopy()})
	api.UpdateInstances(instances)

	require.NoError(t, api.AssignPrivatePrefixesVMSS(t.Context(), "0", "vmss-tiny", "s-tiny", "eth0", 1))
	err := api.AssignPrivatePrefixesVMSS(t.Context(), "0", "vmss-tiny", "s-tiny", "eth0", 1)
	require.Error(t, err, "second /28 allocation on a /28 subnet should fail")
}

func TestSetLimiter(t *testing.T) {
	cidr := netip.MustParsePrefix("10.0.0.0/16")
	subnet := &ipamTypes.Subnet{ID: "s-1", CIDR: cidr, AvailableAddresses: 100}
	api := NewAPI([]*ipamTypes.Subnet{subnet}, []*ipamTypes.VirtualNetwork{{ID: "v-1"}})
	require.NotNil(t, api)

	api.SetLimiter(10.0, 2)
	_, err := api.GetInstances(t.Context(), ipamTypes.SubnetMap{})
	require.NoError(t, err)
}
