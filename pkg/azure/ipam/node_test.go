// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/operator/pkg/ipam/nodemanager"
	"github.com/cilium/cilium/pkg/azure/api/mock"
	"github.com/cilium/cilium/pkg/azure/types"
	iputil "github.com/cilium/cilium/pkg/ip"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"

	// Register the Azure resource-ID parser so AzureInterface.SetID() can
	// populate the VMSS/VM/RG fields used by the release path.
	_ "github.com/cilium/cilium/pkg/azure/types/azureid"
)

func TestGetMaximumAllocatableIPv4(t *testing.T) {
	n := &Node{}
	require.Equal(t, types.InterfaceAddressLimit, n.GetMaximumAllocatableIPv4())
}

const testInstanceID = "/subscriptions/sub/resourceGroups/g/providers/Microsoft.Compute/virtualMachineScaleSets/vmss/virtualMachines/0"

func addr(ip string) iputil.Addr {
	return iputil.AddrFrom(netip.MustParseAddr(ip))
}

// addrWithName builds a Succeeded AzureAddress with both IP and IPConfig name set.
func addrWithName(ip, name string) types.AzureAddress {
	a := types.AzureAddress{IP: addr(ip), Subnet: "subnet-a", State: types.StateSucceeded}
	a.SetIPConfigName(name)
	return a
}

func mkIface(t *testing.T, name string, primary iputil.Addr, addresses ...types.AzureAddress) *types.AzureInterface {
	t.Helper()
	iface := &types.AzureInterface{Name: name, State: types.StateSucceeded, IP: primary, Addresses: addresses}
	iface.Subnet.ID = "subnet-a"
	iface.SetID(testInstanceID + "/networkInterfaces/" + name)
	return iface
}

func mkNode(ifaceFilter string, used ipamTypes.AllocationMap, ifaces ...*types.AzureInterface) *Node {
	mgr := &InstancesManager{instances: ipamTypes.NewInstanceMap()}
	for _, iface := range ifaces {
		mgr.instances.Update(testInstanceID, iface)
	}
	k8sObj := &v2.CiliumNode{
		Spec:   v2.NodeSpec{Azure: types.AzureSpec{InterfaceName: ifaceFilter}},
		Status: v2.NodeStatus{IPAM: ipamTypes.IPAMStatus{Used: used}},
	}
	return &Node{k8sObj: k8sObj, manager: mgr, node: &fakeIpamNode{id: testInstanceID}}
}

// fakeIpamNode is a minimal ipamNodeActions stub.
type fakeIpamNode struct{ id string }

func (f *fakeIpamNode) InstanceID() string { return f.id }

func TestPrepareIPRelease(t *testing.T) {
	log := hivetest.Logger(t)

	t.Run("includes free IPs and excludes used", func(t *testing.T) {
		used := ipamTypes.AllocationMap{"10.0.0.3": ipamTypes.AllocationIP{}}
		iface := mkIface(t, "pods", iputil.Addr{},
			addrWithName("10.0.0.1", "pod-00"),
			addrWithName("10.0.0.2", "pod-01"),
			addrWithName("10.0.0.3", "pod-02"),
			addrWithName("10.0.0.4", "pod-03"),
		)
		n := mkNode("", used, iface)
		r := n.PrepareIPRelease(2, log)
		require.Equal(t, iface.ID, r.InterfaceID)
		require.Equal(t, ipamTypes.PoolID("subnet-a"), r.PoolID)
		require.Equal(t, []string{"10.0.0.1", "10.0.0.2"}, r.IPsToRelease)
	})

	t.Run("respects excessIPs cap", func(t *testing.T) {
		iface := mkIface(t, "pods", iputil.Addr{},
			addrWithName("10.0.0.1", "pod-00"),
			addrWithName("10.0.0.2", "pod-01"),
			addrWithName("10.0.0.3", "pod-02"),
		)
		n := mkNode("", ipamTypes.AllocationMap{}, iface)
		r := n.PrepareIPRelease(1, log)
		require.Len(t, r.IPsToRelease, 1)
	})

	t.Run("excludes the primary IPConfiguration", func(t *testing.T) {
		// usePrimary=true layout: the primary is also present in Addresses and
		// equals iface.IP. It must never be selected.
		iface := mkIface(t, "pods", addr("10.0.0.1"),
			addrWithName("10.0.0.1", "pods"),
			addrWithName("10.0.0.2", "pod-01"),
			addrWithName("10.0.0.3", "pod-02"),
		)
		n := mkNode("", ipamTypes.AllocationMap{}, iface)
		r := n.PrepareIPRelease(5, log)
		require.NotContains(t, r.IPsToRelease, "10.0.0.1")
		require.Equal(t, []string{"10.0.0.2", "10.0.0.3"}, r.IPsToRelease)
	})

	t.Run("Spec.Azure.InterfaceName filters interfaces", func(t *testing.T) {
		host := mkIface(t, "primary", iputil.Addr{}, addrWithName("10.0.0.1", "host-00"))
		pods := mkIface(t, "pods", iputil.Addr{},
			addrWithName("10.1.0.1", "pod-00"),
			addrWithName("10.1.0.2", "pod-01"),
		)
		n := mkNode("pods", ipamTypes.AllocationMap{}, host, pods)
		r := n.PrepareIPRelease(5, log)
		require.Equal(t, pods.ID, r.InterfaceID)
		require.NotContains(t, r.IPsToRelease, "10.0.0.1")
	})

	t.Run("picks the interface with the most freeable IPs", func(t *testing.T) {
		few := mkIface(t, "few", iputil.Addr{}, addrWithName("10.0.0.1", "few-00"))
		many := mkIface(t, "many", iputil.Addr{},
			addrWithName("10.1.0.1", "many-00"),
			addrWithName("10.1.0.2", "many-01"),
			addrWithName("10.1.0.3", "many-02"),
		)
		n := mkNode("", ipamTypes.AllocationMap{}, few, many)
		r := n.PrepareIPRelease(5, log)
		require.Equal(t, many.ID, r.InterfaceID)
		require.Len(t, r.IPsToRelease, 3)
	})

	t.Run("excludes addresses not in Succeeded state", func(t *testing.T) {
		bad := types.AzureAddress{IP: addr("10.0.0.99"), Subnet: "subnet-a", State: "failed"}
		bad.SetIPConfigName("broken")
		iface := mkIface(t, "pods", iputil.Addr{}, addrWithName("10.0.0.1", "pod-00"), bad)
		n := mkNode("", ipamTypes.AllocationMap{}, iface)
		r := n.PrepareIPRelease(5, log)
		require.NotContains(t, r.IPsToRelease, "10.0.0.99")
	})

	t.Run("excludes IPv6 addresses", func(t *testing.T) {
		v6 := addrWithName("fd00::2", "v6")
		iface := mkIface(t, "pods", iputil.Addr{}, addrWithName("10.0.0.1", "pod-00"), v6)
		n := mkNode("", ipamTypes.AllocationMap{}, iface)
		r := n.PrepareIPRelease(5, log)
		require.Equal(t, []string{"10.0.0.1"}, r.IPsToRelease)
	})

	t.Run("empty subnet yields empty PoolID", func(t *testing.T) {
		iface := &types.AzureInterface{Name: "pods", State: types.StateSucceeded,
			Addresses: []types.AzureAddress{addrWithName("10.0.0.1", "pod-00")}}
		iface.SetID(testInstanceID + "/networkInterfaces/pods")
		n := mkNode("", ipamTypes.AllocationMap{}, iface)
		r := n.PrepareIPRelease(5, log)
		require.Equal(t, ipamTypes.PoolID(""), r.PoolID)
		require.Equal(t, []string{"10.0.0.1"}, r.IPsToRelease)
	})

	t.Run("no free IPs yields empty action", func(t *testing.T) {
		used := ipamTypes.AllocationMap{"10.0.0.1": ipamTypes.AllocationIP{}}
		iface := mkIface(t, "pods", iputil.Addr{}, addrWithName("10.0.0.1", "pod-00"))
		n := mkNode("", used, iface)
		r := n.PrepareIPRelease(5, log)
		require.Empty(t, r.IPsToRelease)
		require.Empty(t, r.InterfaceID)
	})
}

func TestIPsToConfigNames(t *testing.T) {
	iface := &types.AzureInterface{
		Addresses: []types.AzureAddress{
			addrWithName("10.0.0.1", "pods"),
			addrWithName("10.0.0.2", "pod-01"),
		},
	}
	names, missing := ipsToConfigNames(iface, []string{"10.0.0.1", "10.0.0.99"})
	require.Equal(t, []string{"pods"}, names)
	require.Equal(t, []string{"10.0.0.99"}, missing)
}

func TestReleaseIPs(t *testing.T) {
	ctx := t.Context()

	// newManagerWithMock wires a manager and a mock API that both hold iface,
	// keyed by instanceID. The given IPs are pre-allocated in the mock subnet so
	// a successful release frees them back and availability changes are
	// observable (which proves the SDK actually dropped the right IPConfig).
	newManagerWithMock := func(t *testing.T, instanceID string, iface *types.AzureInterface, allocated ...string) (*InstancesManager, *mock.API) {
		t.Helper()
		subnet := &ipamTypes.Subnet{ID: "subnet-a", CIDR: netip.MustParsePrefix("10.0.0.0/16")}
		api := mock.NewAPI([]*ipamTypes.Subnet{subnet})
		mockInstances := ipamTypes.NewInstanceMap()
		mockInstances.Update(instanceID, iface.DeepCopy())
		api.UpdateInstances(mockInstances)
		for _, ip := range allocated {
			require.NoError(t, api.AllocateSubnetIP("subnet-a", ip))
		}

		mgr := &InstancesManager{instances: ipamTypes.NewInstanceMap(), api: api}
		mgr.instances.Update(instanceID, iface.DeepCopy())
		return mgr, api
	}

	node := func(mgr *InstancesManager, instanceID string) *Node {
		return &Node{
			k8sObj:  &v2.CiliumNode{},
			manager: mgr,
			node:    &fakeIpamNode{id: instanceID},
		}
	}

	remainingIPs := func(t *testing.T, mgr *InstancesManager, instanceID string) []string {
		t.Helper()
		var ips []string
		mgr.instances.ForeachInterface(instanceID, func(_, _ string, o ipamTypes.Interface) error {
			ips = append(ips, ipsOf(o.(*types.AzureInterface))...)
			return nil
		})
		return ips
	}

	subnetAvail := func(t *testing.T, api *mock.API) int {
		t.Helper()
		subnets, err := api.GetSubnetsByIDs(ctx, []string{"subnet-a"})
		require.NoError(t, err)
		return subnets["subnet-a"].AvailableAddresses
	}

	t.Run("VMSS path translates IPs to names, releases on Azure, and updates the cache", func(t *testing.T) {
		iface := mkIface(t, "pods", addr("10.0.0.1"),
			addrWithName("10.0.0.1", "pods"),
			addrWithName("10.0.0.2", "pod-01"),
			addrWithName("10.0.0.3", "pod-02"),
		)
		mgr, api := newManagerWithMock(t, testInstanceID, iface, "10.0.0.2", "10.0.0.3")
		n := node(mgr, testInstanceID)

		before := subnetAvail(t, api)
		err := n.ReleaseIPs(ctx, releaseAction(iface.ID, "10.0.0.2"))
		require.NoError(t, err)
		require.NotContains(t, remainingIPs(t, mgr, testInstanceID), "10.0.0.2")
		require.Contains(t, remainingIPs(t, mgr, testInstanceID), "10.0.0.3")
		// If the IP->name translation were wrong, the mock would drop nothing and
		// availability would not move. +1 proves "pod-01" (10.0.0.2) was released.
		require.Equal(t, before+1, subnetAvail(t, api), "released IP must be freed on Azure")
	})

	t.Run("VM path passes IPs directly and updates the cache", func(t *testing.T) {
		const vmInstanceID = "/subscriptions/sub/resourceGroups/g/providers/Microsoft.Compute/virtualMachines/vm0"
		iface := &types.AzureInterface{Name: "vm-if", State: types.StateSucceeded, Addresses: []types.AzureAddress{
			addrWithName("10.0.0.5", "primary"),
			addrWithName("10.0.0.6", "secondary"),
		}}
		iface.Subnet.ID = "subnet-a"
		iface.SetID(vmInstanceID + "/networkInterfaces/vm-if")
		require.Empty(t, iface.GetVMScaleSetName(), "fixture must route through the VM path")

		mgr, api := newManagerWithMock(t, vmInstanceID, iface, "10.0.0.6")
		n := node(mgr, vmInstanceID)

		before := subnetAvail(t, api)
		err := n.ReleaseIPs(ctx, releaseAction(iface.ID, "10.0.0.6"))
		require.NoError(t, err)
		require.NotContains(t, remainingIPs(t, mgr, vmInstanceID), "10.0.0.6")
		require.Equal(t, before+1, subnetAvail(t, api))
	})

	t.Run("VMSS path errors when an IP has no IPConfig name mapping", func(t *testing.T) {
		// Address with no IPConfig name simulates a stale/partial cache.
		noName := types.AzureAddress{IP: addr("10.0.0.2"), Subnet: "subnet-a", State: types.StateSucceeded}
		iface := mkIface(t, "pods", addr("10.0.0.1"), addrWithName("10.0.0.1", "pods"), noName)
		mgr, _ := newManagerWithMock(t, testInstanceID, iface)
		n := node(mgr, testInstanceID)

		err := n.ReleaseIPs(ctx, releaseAction(iface.ID, "10.0.0.2"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing IPConfiguration name mapping")
		// Cache must be untouched on error.
		require.Contains(t, remainingIPs(t, mgr, testInstanceID), "10.0.0.2")
	})

	t.Run("cache is untouched when the SDK release fails", func(t *testing.T) {
		iface := mkIface(t, "pods", addr("10.0.0.1"),
			addrWithName("10.0.0.1", "pods"),
			addrWithName("10.0.0.2", "pod-01"),
		)
		mgr, api := newManagerWithMock(t, testInstanceID, iface)
		api.SetMockError(mock.UnassignPrivateIpAddressesVMSS, errors.New("azure boom"))
		n := node(mgr, testInstanceID)

		err := n.ReleaseIPs(ctx, releaseAction(iface.ID, "10.0.0.2"))
		require.Error(t, err)
		require.Contains(t, remainingIPs(t, mgr, testInstanceID), "10.0.0.2",
			"cache must not be mutated when the release fails")
	})

	t.Run("empty action is a no-op", func(t *testing.T) {
		iface := mkIface(t, "pods", iputil.Addr{}, addrWithName("10.0.0.2", "pod-01"))
		mgr, _ := newManagerWithMock(t, testInstanceID, iface)
		n := node(mgr, testInstanceID)
		require.NoError(t, n.ReleaseIPs(ctx, releaseAction(iface.ID)))
	})
}

func TestRemoveIPsFromInterface(t *testing.T) {
	iface := mkIface(t, "pods", iputil.Addr{},
		addrWithName("10.0.0.1", "pod-00"),
		addrWithName("10.0.0.2", "pod-01"),
	)
	mgr := &InstancesManager{instances: ipamTypes.NewInstanceMap(), logger: hivetest.Logger(t)}
	mgr.instances.Update(testInstanceID, iface)

	mgr.RemoveIPsFromInterface(testInstanceID, iface.ID, []string{"10.0.0.1"})

	var ips []string
	mgr.instances.ForeachInterface(testInstanceID, func(_, _ string, o ipamTypes.Interface) error {
		ips = ipsOf(o.(*types.AzureInterface))
		return nil
	})
	require.Equal(t, []string{"10.0.0.2"}, ips)

	// Unknown interface is a safe no-op.
	mgr.RemoveIPsFromInterface(testInstanceID, "does-not-exist", []string{"10.0.0.2"})
}

func releaseAction(interfaceID string, ips ...string) *nodemanager.ReleaseAction {
	return &nodemanager.ReleaseAction{InterfaceID: interfaceID, IPsToRelease: ips}
}

func ipsOf(iface *types.AzureInterface) []string {
	ips := make([]string, 0, len(iface.Addresses))
	for _, a := range iface.Addresses {
		ips = append(ips, a.IP.String())
	}
	return ips
}
