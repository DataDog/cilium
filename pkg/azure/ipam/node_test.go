// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/azure/types"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func TestGetMaximumAllocatableIPv4(t *testing.T) {
	n := &Node{}
	require.Equal(t, types.InterfaceAddressLimit, n.GetMaximumAllocatableIPv4())
}

// fakeIpamNode is a minimal ipamNodeActions stub used by PrepareIPRelease tests.
type fakeIpamNode struct {
	id string
}

func (f *fakeIpamNode) InstanceID() string { return f.id }

// addrWithName builds an AzureAddress with both IP and IPConfig name set.
func addrWithName(ip, name, subnet string) types.AzureAddress {
	addr := types.AzureAddress{IP: ip, Subnet: subnet, State: types.StateSucceeded}
	addr.SetIPConfigName(name)
	return addr
}

// addrPrimary builds a primary AzureAddress with IP and IPConfig name set.
func addrPrimary(ip, name, subnet string) types.AzureAddress {
	addr := addrWithName(ip, name, subnet)
	addr.SetPrimary(true)
	return addr
}

func TestPrepareIPRelease(t *testing.T) {
	const instanceID = "/subscriptions/sub/resourceGroups/g/providers/Microsoft.Compute/virtualMachineScaleSets/vmss/virtualMachines/0"

	mkIface := func(name string, addresses []types.AzureAddress) *types.AzureInterface {
		iface := &types.AzureInterface{Name: name, State: types.StateSucceeded, Addresses: addresses}
		iface.SetID("/subscriptions/sub/resourceGroups/g/providers/Microsoft.Compute/virtualMachineScaleSets/vmss/virtualMachines/0/networkInterfaces/" + name)
		return iface
	}
	mkNode := func(t *testing.T, ifaceFilter string, used ipamTypes.AllocationMap, ifaces ...*types.AzureInterface) *Node {
		t.Helper()
		mgr := &InstancesManager{instances: ipamTypes.NewInstanceMap()}
		for _, iface := range ifaces {
			mgr.instances.Update(instanceID, ipamTypes.InterfaceRevision{Resource: iface})
		}
		k8sObj := &v2.CiliumNode{
			Spec:   v2.NodeSpec{Azure: types.AzureSpec{InterfaceName: ifaceFilter}},
			Status: v2.NodeStatus{IPAM: ipamTypes.IPAMStatus{Used: used}},
		}
		return &Node{k8sObj: k8sObj, manager: mgr, node: &fakeIpamNode{id: instanceID}}
	}
	log := hivetest.Logger(t)

	t.Run("includes free IPs and excludes used", func(t *testing.T) {
		used := ipamTypes.AllocationMap{"10.0.0.3": ipamTypes.AllocationIP{}}
		iface := mkIface("pods", []types.AzureAddress{
			addrWithName("10.0.0.1", "pods", "subnet-a"),
			addrWithName("10.0.0.2", "pod-01", "subnet-a"),
			addrWithName("10.0.0.3", "pod-02", "subnet-a"),
			addrWithName("10.0.0.4", "pod-03", "subnet-a"),
		})
		n := mkNode(t, "", used, iface)
		r := n.PrepareIPRelease(2, log)
		require.Equal(t, iface.ID, r.InterfaceID)
		require.Equal(t, ipamTypes.PoolID("subnet-a"), r.PoolID)
		require.Equal(t, []string{"10.0.0.1", "10.0.0.2"}, r.IPsToRelease)
	})

	t.Run("respects excessIPs cap", func(t *testing.T) {
		used := ipamTypes.AllocationMap{}
		iface := mkIface("pods", []types.AzureAddress{
			addrWithName("10.0.0.1", "pods", "subnet-a"),
			addrWithName("10.0.0.2", "pod-01", "subnet-a"),
			addrWithName("10.0.0.3", "pod-02", "subnet-a"),
			addrWithName("10.0.0.4", "pod-03", "subnet-a"),
		})
		n := mkNode(t, "", used, iface)
		r := n.PrepareIPRelease(1, log)
		require.Len(t, r.IPsToRelease, 1)
	})

	t.Run("excludes primary IPConfigurations to avoid jamming the batch", func(t *testing.T) {
		// Mirrors the live arbok layout: primary first, free, on the
		// filter-matched interface. Must not be selected.
		used := ipamTypes.AllocationMap{}
		iface := mkIface("pods", []types.AzureAddress{
			addrPrimary("10.0.0.1", "pods", "subnet-a"),
			addrWithName("10.0.0.2", "pod-01", "subnet-a"),
			addrWithName("10.0.0.3", "pod-02", "subnet-a"),
		})
		n := mkNode(t, "", used, iface)
		r := n.PrepareIPRelease(5, log)
		require.NotContains(t, r.IPsToRelease, "10.0.0.1")
		require.ElementsMatch(t, []string{"10.0.0.2", "10.0.0.3"}, r.IPsToRelease)
	})

	t.Run("Spec.Azure.InterfaceName filters interfaces", func(t *testing.T) {
		used := ipamTypes.AllocationMap{}
		host := mkIface("primary", []types.AzureAddress{
			addrWithName("10.0.0.1", "hosts", "subnet-host"),
		})
		pods := mkIface("pods", []types.AzureAddress{
			addrWithName("10.1.0.1", "pods", "subnet-pods"),
			addrWithName("10.1.0.2", "pod-01", "subnet-pods"),
		})
		n := mkNode(t, "pods", used, host, pods)
		r := n.PrepareIPRelease(5, log)
		require.Equal(t, pods.ID, r.InterfaceID)
		for _, ip := range r.IPsToRelease {
			require.NotEqual(t, "10.0.0.1", ip, "must not pick host IP")
		}
	})

	t.Run("picks interface with the most freeable IPs", func(t *testing.T) {
		used := ipamTypes.AllocationMap{}
		few := mkIface("few", []types.AzureAddress{
			addrWithName("10.0.0.1", "few-1", "subnet-a"),
		})
		many := mkIface("many", []types.AzureAddress{
			addrWithName("10.1.0.1", "many-1", "subnet-b"),
			addrWithName("10.1.0.2", "many-2", "subnet-b"),
			addrWithName("10.1.0.3", "many-3", "subnet-b"),
		})
		n := mkNode(t, "", used, few, many)
		r := n.PrepareIPRelease(5, log)
		require.Equal(t, many.ID, r.InterfaceID)
		require.Len(t, r.IPsToRelease, 3)
	})

	t.Run("excludes addresses not in Succeeded state", func(t *testing.T) {
		used := ipamTypes.AllocationMap{}
		bad := types.AzureAddress{IP: "10.0.0.99", Subnet: "subnet-a", State: "failed"}
		bad.SetIPConfigName("broken")
		iface := mkIface("pods", []types.AzureAddress{
			addrWithName("10.0.0.1", "pods", "subnet-a"),
			bad,
		})
		n := mkNode(t, "", used, iface)
		r := n.PrepareIPRelease(5, log)
		require.NotContains(t, r.IPsToRelease, "10.0.0.99")
	})
}

func TestIPsToConfigNames(t *testing.T) {
	iface := &types.AzureInterface{
		Addresses: []types.AzureAddress{
			addrWithName("10.0.0.1", "pods", "s"),
			addrWithName("10.0.0.2", "pod-01", "s"),
		},
	}
	names, missing := ipsToConfigNames(iface, []string{"10.0.0.1", "10.0.0.99"})
	require.Equal(t, []string{"pods"}, names)
	require.Equal(t, []string{"10.0.0.99"}, missing)
}
