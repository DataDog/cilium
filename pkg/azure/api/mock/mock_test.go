// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mock

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/azure/types"
	// Register the Azure resource-ID parser so AzureInterface.GetVMID()
	// resolves, which the AssignPrivateIpAddressesVMSS lookup compares against.
	_ "github.com/cilium/cilium/pkg/azure/types/azureid"
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
	resource.ID = ifaceID
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

	err = api.AssignPrivateIpAddressesVMSS(t.Context(), "vm1", "vmss1", "s-1", "eth0", 2, 0)
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
	resource.ID = vmIfaceID
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
	err = api.AssignPrivateIpAddressesVMSS(t.Context(), "vmss1", "i-1", "s-1", "eth0", 0, 0)
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

func TestMockAssignPrefixes(t *testing.T) {
	api := NewAPI([]*ipamTypes.Subnet{{ID: "s-1", CIDR: netip.MustParsePrefix("10.0.0.0/26")}})
	instances := ipamTypes.NewInstanceMap()
	resource := &types.AzureInterface{Name: "eth0"}
	resource.ID = "/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Network/networkInterfaces/eth0"
	instances.Update("vm1", resource.DeepCopy())
	api.UpdateInstances(instances)

	require.NoError(t, api.AssignPrivateIpAddressesVM(t.Context(), "s-1", "eth0", 2, types.PrefixLengthIPv4))
	require.Equal(t, 1, api.PrefixRequests())

	err := api.AssignPrivateIpAddressesVM(t.Context(), "s-1", "eth0", 1, types.PrefixLengthIPv4)
	require.ErrorContains(t, err, "SubnetIsFull")

	require.NoError(t, api.AssignPrivateIpAddressesVM(t.Context(), "s-1", "eth0", 1, 0))

	var prefixes []string
	var addresses []string
	api.ParseInterfacesIntoInstanceMap(nil, nil).ForeachInterface("", func(_, _ string, iface ipamTypes.Interface) error {
		for _, prefix := range iface.(*types.AzureInterface).Prefixes {
			prefixes = append(prefixes, prefix.CIDR.String())
		}
		for _, address := range iface.(*types.AzureInterface).Addresses {
			addresses = append(addresses, address.IP.String())
		}
		return nil
	})
	require.Equal(t, []string{"10.0.0.16/28", "10.0.0.32/28"}, prefixes)
	require.Len(t, addresses, 1)
	for _, prefix := range prefixes {
		require.False(t, netip.MustParsePrefix(prefix).Contains(netip.MustParseAddr(addresses[0])))
	}

	api.SetPrefixError(errors.New("prefix error"))
	require.ErrorContains(t, api.AssignPrivateIpAddressesVM(t.Context(), "s-1", "eth0", 1, types.PrefixLengthIPv4), "prefix error")
}
