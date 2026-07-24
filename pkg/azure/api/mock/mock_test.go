// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mock

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	azureAPI "github.com/cilium/cilium/pkg/azure/api"
	"github.com/cilium/cilium/pkg/azure/types"

	// Register the Azure resource-ID parser so AzureInterface.SetID() can
	// populate VMSS/VM/RG fields used by AssignPrivateIpAddressesVMSS lookup.
	_ "github.com/cilium/cilium/pkg/azure/types/azureid"
	iputil "github.com/cilium/cilium/pkg/ip"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
)

func TestMock(t *testing.T) {
	cidr := netip.MustParsePrefix("10.0.0.0/16")
	subnet := &ipamTypes.Subnet{ID: "s-1", CIDR: cidr, AvailableAddresses: 65534}
	api := NewAPI([]*ipamTypes.Subnet{subnet})
	require.NotNil(t, api)

	nics, err := api.ListAllNetworkInterfaces(t.Context())
	require.NoError(t, err)
	instances := api.ParseInterfacesIntoInstanceMap(nics, ipamTypes.SubnetMap{})
	require.Equal(t, 0, instances.NumInstances())

	subnets, err := api.GetSubnetsByIDs(t.Context(), []string{"s-1"})
	require.NoError(t, err)
	require.Len(t, subnets, 1)
	require.Equal(t, subnet, subnets["s-1"])

	ifaceID := "/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm1/networkInterfaces/vmss11"
	instances = ipamTypes.NewInstanceMap()
	resource := &types.AzureInterface{Name: "eth0"}
	resource.SetID(ifaceID)
	instances.Update("vm1", resource.DeepCopy())
	api.UpdateInstances(instances)
	nics, err = api.ListAllNetworkInterfaces(t.Context())
	require.NoError(t, err)
	instances = api.ParseInterfacesIntoInstanceMap(nics, ipamTypes.SubnetMap{})
	require.Equal(t, 1, instances.NumInstances())
	instances.ForeachInterface("", func(instanceID, interfaceID string, iface ipamTypes.Interface) error {
		require.Equal(t, "vm1", instanceID)
		require.Equal(t, ifaceID, interfaceID)
		return nil
	})

	err = api.AssignPrivateIpAddressesVMSS(t.Context(), "vm1", "vmss1", "s-1", "eth0", 2)
	require.NoError(t, err)
	nics, err = api.ListAllNetworkInterfaces(t.Context())
	require.NoError(t, err)
	instances = api.ParseInterfacesIntoInstanceMap(nics, ipamTypes.SubnetMap{})
	require.Equal(t, 1, instances.NumInstances())
	instances.ForeachInterface("", func(instanceID, interfaceID string, iface ipamTypes.Interface) error {
		require.Equal(t, "vm1", instanceID)
		require.Equal(t, ifaceID, interfaceID)

		azIface, ok := iface.(*types.AzureInterface)
		require.True(t, ok)
		require.Len(t, azIface.Addresses, 2)
		return nil
	})

	vmIfaceID := "/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Network/networkInterfaces/vm22-if"
	vmInstances := ipamTypes.NewInstanceMap()
	resource = &types.AzureInterface{Name: "eth0"}
	resource.SetID(vmIfaceID)
	vmInstances.Update("vm2", resource.DeepCopy())
	require.NoError(t, err)
	require.Equal(t, 1, vmInstances.NumInstances())
	vmInstances.ForeachInterface("", func(instanceID, interfaceID string, iface ipamTypes.Interface) error {
		require.Equal(t, "vm2", instanceID)
		require.Equal(t, vmIfaceID, interfaceID)
		return nil
	})

}

func TestSetMockError(t *testing.T) {
	api := NewAPI([]*ipamTypes.Subnet{})
	require.NotNil(t, api)

	mockError := errors.New("error")

	api.SetMockError(ListAllNetworkInterfaces, mockError)
	_, err := api.ListAllNetworkInterfaces(t.Context())
	require.ErrorIs(t, err, mockError)

	api.SetMockError(GetSubnetsByIDs, mockError)
	_, err = api.GetSubnetsByIDs(t.Context(), nil)
	require.ErrorIs(t, err, mockError)

	api.SetMockError(AssignPrivateIpAddressesVMSS, mockError)
	err = api.AssignPrivateIpAddressesVMSS(t.Context(), "vmss1", "i-1", "s-1", "eth0", 0)
	require.ErrorIs(t, err, mockError)
}

func TestSetLimiter(t *testing.T) {
	cidr := netip.MustParsePrefix("10.0.0.0/16")
	subnet := &ipamTypes.Subnet{ID: "s-1", CIDR: cidr, AvailableAddresses: 100}
	api := NewAPI([]*ipamTypes.Subnet{subnet})
	require.NotNil(t, api)

	api.SetLimiter(10.0, 2)
	_, err := api.ListAllNetworkInterfaces(t.Context())
	require.NoError(t, err)
}

// addrWithName builds an AzureAddress with both IP and IPConfig name set.
func addrWithName(ip, name, subnet string) types.AzureAddress {
	addr := types.AzureAddress{IP: iputil.AddrFrom(netip.MustParseAddr(ip)), Subnet: subnet, State: types.StateSucceeded}
	addr.SetIPConfigName(name)
	return addr
}

func TestUnassignPrivateIpAddressesVMSS(t *testing.T) {
	cidr := netip.MustParsePrefix("10.0.0.0/16")
	subnet := &ipamTypes.Subnet{ID: "s-1", CIDR: cidr, AvailableAddresses: 65534}
	api := NewAPI([]*ipamTypes.Subnet{subnet})

	const vmFullID = "/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss1/virtualMachines/0"
	const ifaceID = vmFullID + "/networkInterfaces/pods"
	// Per AzureInterface.extractIDs, GetVMID returns just the instance index.
	const vmIndex = "0"

	resource := &types.AzureInterface{
		Name:  "pods",
		State: types.StateSucceeded,
		Addresses: []types.AzureAddress{
			addrWithName("10.0.0.1", "pods", "s-1"),
			addrWithName("10.0.0.2", "pod-01", "s-1"),
			addrWithName("10.0.0.3", "pod-02", "s-1"),
		},
	}
	resource.SetID(ifaceID)

	instances := ipamTypes.NewInstanceMap()
	instances.Update(vmFullID, resource.DeepCopy())
	api.UpdateInstances(instances)

	// Pre-allocate the IPs so a release frees them back observably.
	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		require.NoError(t, api.subnets["s-1"].allocator.Allocate(netip.MustParseAddr(ip)))
	}

	t.Run("removes requested IPConfigurations and frees them to the subnet", func(t *testing.T) {
		before, err := api.GetSubnetsByIDs(t.Context(), []string{"s-1"})
		require.NoError(t, err)

		err = api.UnassignPrivateIpAddressesVMSS(t.Context(), vmIndex, "vmss1", "pods", []string{"pod-02"})
		require.NoError(t, err)

		api.instances.ForeachInterface("", func(_, _ string, rev ipamTypes.Interface) error {
			intf := rev.(*types.AzureInterface)
			require.Len(t, intf.Addresses, 2)
			for _, a := range intf.Addresses {
				require.NotEqual(t, "pod-02", a.IPConfigName())
			}
			return nil
		})

		after, err := api.GetSubnetsByIDs(t.Context(), []string{"s-1"})
		require.NoError(t, err)
		require.Equal(t, before["s-1"].AvailableAddresses+1, after["s-1"].AvailableAddresses,
			"released IP must be freed back to the subnet")
	})

	t.Run("primary block returns PrimaryReleaseError without mutating", func(t *testing.T) {
		before, err := api.GetSubnetsByIDs(t.Context(), []string{"s-1"})
		require.NoError(t, err)

		api.SetPrimaryIPs(ifaceID, "pods")
		err = api.UnassignPrivateIpAddressesVMSS(t.Context(), vmIndex, "vmss1", "pods", []string{"pods"})
		var pErr *azureAPI.PrimaryReleaseError
		require.ErrorAs(t, err, &pErr)
		require.Equal(t, "pods", pErr.InterfaceName)
		require.Contains(t, pErr.Items, "pods")

		api.instances.ForeachInterface("", func(_, _ string, rev ipamTypes.Interface) error {
			intf := rev.(*types.AzureInterface)
			names := make([]string, 0, len(intf.Addresses))
			for _, a := range intf.Addresses {
				names = append(names, a.IPConfigName())
			}
			require.Contains(t, names, "pods", "primary IPConfig must remain on the NIC")
			return nil
		})

		// Fail-closed must not leak the primary's IP into the subnet allocator.
		after, err := api.GetSubnetsByIDs(t.Context(), []string{"s-1"})
		require.NoError(t, err)
		require.Equal(t, before["s-1"].AvailableAddresses, after["s-1"].AvailableAddresses,
			"primary block must not change subnet availability")
	})
}

func TestUnassignPrivateIpAddressesVM(t *testing.T) {
	cidr := netip.MustParsePrefix("10.0.0.0/16")
	subnet := &ipamTypes.Subnet{ID: "s-1", CIDR: cidr, AvailableAddresses: 65534}
	api := NewAPI([]*ipamTypes.Subnet{subnet})

	const vmIfaceID = "/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Network/networkInterfaces/vm-if"

	resource := &types.AzureInterface{
		Name:  "vm-if",
		State: types.StateSucceeded,
		Addresses: []types.AzureAddress{
			addrWithName("10.0.0.5", "primary", "s-1"),
			addrWithName("10.0.0.6", "secondary", "s-1"),
		},
	}
	resource.SetID(vmIfaceID)

	instances := ipamTypes.NewInstanceMap()
	instances.Update("vm-instance", resource.DeepCopy())
	api.UpdateInstances(instances)

	t.Run("removes requested IP", func(t *testing.T) {
		err := api.UnassignPrivateIpAddressesVM(t.Context(), "vm-if", []string{"10.0.0.6"})
		require.NoError(t, err)
		api.instances.ForeachInterface("", func(_, _ string, rev ipamTypes.Interface) error {
			intf := rev.(*types.AzureInterface)
			require.Len(t, intf.Addresses, 1)
			require.Equal(t, "10.0.0.5", intf.Addresses[0].IP.String())
			return nil
		})
	})

	t.Run("primary block returns error without mutation", func(t *testing.T) {
		api.SetPrimaryIPs("vm-if", "10.0.0.5")
		err := api.UnassignPrivateIpAddressesVM(t.Context(), "vm-if", []string{"10.0.0.5"})
		var pErr *azureAPI.PrimaryReleaseError
		require.ErrorAs(t, err, &pErr)
	})
}
