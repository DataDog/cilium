// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"

	apimock "github.com/cilium/cilium/pkg/azure/api/mock"
	"github.com/cilium/cilium/pkg/azure/types"
	iputil "github.com/cilium/cilium/pkg/ip"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func newCapacityTestNode(t *testing.T, ifaces []*types.AzureInterface, usePrimary bool) *Node {
	t.Helper()
	return newCapacityTestNodeWithSpec(t, ifaces, usePrimary, types.AzureSpec{InterfaceName: "eth0"})
}

func newCapacityTestNodeWithSpec(t *testing.T, ifaces []*types.AzureInterface, usePrimary bool, spec types.AzureSpec) *Node {
	t.Helper()
	m := ipamTypes.NewInstanceMap()
	for _, iface := range ifaces {
		m.Update("vm1", iface.DeepCopy())
	}
	manager := &InstancesManager{
		instances:  m,
		api:        apimock.NewAPI(nil),
		usePrimary: usePrimary,
	}
	obj := &v2.CiliumNode{
		Spec: v2.NodeSpec{
			InstanceID: "vm1",
			Azure:      spec,
		},
	}
	node := manager.CreateNode(obj, nil).(*Node)
	node.UpdatedNode(obj)
	return node
}

func newCapacityTestInterface(name, id, primaryIP string, secondaryIPs ...string) *types.AzureInterface {
	addrs := make([]types.AzureAddress, 0, len(secondaryIPs))
	for _, ip := range secondaryIPs {
		addrs = append(addrs, types.AzureAddress{
			IP:    iputil.AddrFrom(netip.MustParseAddr(ip)),
			State: types.StateSucceeded,
		})
	}
	iface := &types.AzureInterface{
		Name:          name,
		IP:            iputil.AddrFrom(netip.MustParseAddr(primaryIP)),
		SecurityGroup: "sg1",
		Subnet:        types.AzureSubnet{ID: "subnet-1"},
		Addresses:     addrs,
		State:         types.StateSucceeded,
	}
	iface.ID = id
	return iface
}

func withCapacityTestPrefixes(iface *types.AzureInterface, state string, cidrs ...string) *types.AzureInterface {
	for _, cidr := range cidrs {
		iface.Prefixes = append(iface.Prefixes, types.AzurePrefix{
			CIDR:  iputil.PrefixFrom(netip.MustParsePrefix(cidr)),
			State: state,
		})
	}
	return iface
}

func capacityTestAddresses(prefix string, count int) []string {
	addr := netip.MustParseAddr(prefix)
	addrs := make([]string, 0, count)
	for range count {
		addr = addr.Next()
		addrs = append(addrs, addr.String())
	}
	return addrs
}

func capacityTestPrefixes(first string, count int) []string {
	prefix := netip.MustParsePrefix(first)
	prefixes := make([]string, 0, count)
	for range count {
		prefixes = append(prefixes, prefix.String())
		next := prefix.Addr()
		for range types.PrefixSizeIPv4 {
			next = next.Next()
		}
		prefix = netip.PrefixFrom(next, prefix.Bits())
	}
	return prefixes
}

func TestENIIPAMCapacityAccounting(t *testing.T) {
	assert := assert.New(t)
	iface := newCapacityTestInterface(
		"eth0",
		"/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm1/networkInterfaces/vmss11",
		"1.1.1.1",
		"1.1.1.2",
	)
	n := newCapacityTestNode(t, []*types.AzureInterface{iface}, false)
	_, stats, err := n.ResyncInterfacesAndIPs(t.Context(), hivetest.Logger(t))
	assert.NoError(err)
	assert.Equal(255, stats.NodeCapacity)
}

func TestENIIPAMCapacityAccountingUsePrimary(t *testing.T) {
	assert := assert.New(t)
	iface := newCapacityTestInterface(
		"eth0",
		"/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm1/networkInterfaces/vmss11",
		"1.1.1.1",
		"1.1.1.1",
		"1.1.1.2",
	)
	n := newCapacityTestNode(t, []*types.AzureInterface{iface}, true)
	_, stats, err := n.ResyncInterfacesAndIPs(t.Context(), hivetest.Logger(t))
	assert.NoError(err)
	assert.Equal(256, stats.NodeCapacity)
}

func TestENIIPAMCapacityAccountingMultiNIC(t *testing.T) {
	assert := assert.New(t)
	iface1 := newCapacityTestInterface(
		"eth0",
		"/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm1/networkInterfaces/nic1",
		"1.1.1.1",
	)
	iface2 := newCapacityTestInterface(
		"eth1",
		"/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm1/networkInterfaces/nic2",
		"1.1.2.1",
	)
	n := newCapacityTestNode(t, []*types.AzureInterface{iface1, iface2}, false)
	_, stats, err := n.ResyncInterfacesAndIPs(t.Context(), hivetest.Logger(t))
	assert.NoError(err)
	assert.Equal(255, stats.NodeCapacity)

	n = newCapacityTestNodeWithSpec(t, []*types.AzureInterface{iface1, iface2}, false, types.AzureSpec{})
	_, stats, err = n.ResyncInterfacesAndIPs(t.Context(), hivetest.Logger(t))
	assert.NoError(err)
	assert.Equal(510, stats.NodeCapacity)
}

func TestENIIPAMCapacityAccountingMultiNICUsePrimary(t *testing.T) {
	assert := assert.New(t)
	iface1 := newCapacityTestInterface(
		"eth0",
		"/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm1/networkInterfaces/nic1",
		"1.1.1.1",
		"1.1.1.1",
	)
	iface2 := newCapacityTestInterface(
		"eth1",
		"/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm1/networkInterfaces/nic2",
		"1.1.2.1",
		"1.1.2.1",
	)
	n := newCapacityTestNode(t, []*types.AzureInterface{iface1, iface2}, true)
	_, stats, err := n.ResyncInterfacesAndIPs(t.Context(), hivetest.Logger(t))
	assert.NoError(err)
	assert.Equal(257, stats.NodeCapacity)
}

func TestENIIPAMCapacityAccountingPrefixes(t *testing.T) {
	assert := assert.New(t)
	newInterfaces := func() []*types.AzureInterface {
		iface1 := withCapacityTestPrefixes(newCapacityTestInterface(
			"eth0",
			"/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm1/networkInterfaces/nic1",
			"1.1.1.1",
			"1.1.1.2",
		), types.StateSucceeded, "1.1.1.16/28", "1.1.1.32/28")
		withCapacityTestPrefixes(iface1, types.StateUpdating, "1.1.1.48/28")
		withCapacityTestPrefixes(iface1, "failed", "1.1.1.64/28")
		iface2 := withCapacityTestPrefixes(newCapacityTestInterface(
			"eth1",
			"/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm1/networkInterfaces/nic2",
			"1.1.2.1",
		), types.StateSucceeded, capacityTestPrefixes("1.1.3.0/28", 20)...)
		return []*types.AzureInterface{iface1, iface2}
	}

	n := newCapacityTestNodeWithSpec(t, newInterfaces(), false, types.AzureSpec{DisablePrefixDelegation: new(false)})
	available, stats, err := n.ResyncInterfacesAndIPs(t.Context(), hivetest.Logger(t))
	assert.NoError(err)
	assert.Len(available, 1)
	assert.Equal(22*types.PrefixSizeIPv4, stats.NodeIPv4PrefixedAddresses)
	// eth0: 256 - primary, 1 address and 4 prefixes; eth1: 256 - primary and 20 prefixes
	assert.Equal(1+22*types.PrefixSizeIPv4+250+235, stats.NodeCapacity)

	n = newCapacityTestNodeWithSpec(t, newInterfaces(), false, types.AzureSpec{DisablePrefixDelegation: new(true)})
	_, stats, err = n.ResyncInterfacesAndIPs(t.Context(), hivetest.Logger(t))
	assert.NoError(err)
	assert.Equal(22*types.PrefixSizeIPv4, stats.NodeIPv4PrefixedAddresses)

	n = newCapacityTestNodeWithSpec(t, newInterfaces(), false, types.AzureSpec{})
	_, stats, err = n.ResyncInterfacesAndIPs(t.Context(), hivetest.Logger(t))
	assert.NoError(err)
	assert.Zero(stats.NodeIPv4PrefixedAddresses)
	assert.Equal(1+250+235, stats.NodeCapacity)
}

func TestENIIPAMCapacityAccountingOverfullInterface(t *testing.T) {
	assert := assert.New(t)
	iface := newCapacityTestInterface(
		"eth0",
		"/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm1/networkInterfaces/nic1",
		"1.1.1.1",
		capacityTestAddresses("1.1.1.1", 256)...,
	)
	n := newCapacityTestNode(t, []*types.AzureInterface{iface}, false)
	available, stats, err := n.ResyncInterfacesAndIPs(t.Context(), hivetest.Logger(t))
	assert.NoError(err)
	assert.Len(available, 256)
	assert.Equal(256, stats.NodeCapacity)
	assert.Zero(stats.RemainingAvailableInterfaceCount)
}

func TestGetAttachedCIDRsIncludesPrefixes(t *testing.T) {
	iface := newCapacityTestInterface(
		"eth0",
		"/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm1/networkInterfaces/nic1",
		"1.1.1.1",
		"1.1.1.2",
	)
	withCapacityTestPrefixes(iface, types.StateSucceeded, "1.1.1.16/28")
	withCapacityTestPrefixes(iface, types.StateUpdating, "1.1.1.32/28")
	withCapacityTestPrefixes(iface, "failed", "1.1.1.48/28")
	withCapacityTestPrefixes(iface, types.StateSucceeded, "2001:db8::/124")
	n := newCapacityTestNode(t, []*types.AzureInterface{iface}, false)

	assert.ElementsMatch(t, []netip.Prefix{
		netip.MustParsePrefix("1.1.1.2/32"),
		netip.MustParsePrefix("1.1.1.16/28"),
		netip.MustParsePrefix("1.1.1.32/28"),
		netip.MustParsePrefix("1.1.1.48/28"),
	}, n.GetAttachedCIDRs())
}
