// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apimock "github.com/cilium/cilium/pkg/azure/api/mock"
	"github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/ipam"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

const (
	testVMSSInstanceID = "/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm1"
	testVMSSIfaceID    = "/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm1/networkInterfaces/eth0"
	testVMInstanceID   = "/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachines/vm1"
	testVMIfaceID      = "/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Network/networkInterfaces/eth0"
)

func TestGetMaximumAllocatableIPv4(t *testing.T) {
	n := &Node{}
	require.Equal(t, types.InterfaceAddressLimit, n.GetMaximumAllocatableIPv4())
}

type fakeNodeActions string

func (f fakeNodeActions) InstanceID() string { return string(f) }

func newAzureInterface(t *testing.T, id, name string, ips []string) *types.AzureInterface {
	t.Helper()
	iface := &types.AzureInterface{
		Name:  name,
		State: types.StateSucceeded,
	}
	for _, ip := range ips {
		iface.Addresses = append(iface.Addresses, types.AzureAddress{
			IP:     ip,
			Subnet: "subnet-1",
			State:  types.StateSucceeded,
		})
	}
	iface.SetID(id)
	return iface
}

func newReleaseTestNode(t *testing.T, instanceID string, iface *types.AzureInterface, requiredIfaceName string, used map[string]struct{}) (*Node, *apimock.API) {
	t.Helper()

	api := apimock.NewAPI([]*ipamTypes.Subnet{
		{ID: "subnet-1", CIDR: netip.MustParsePrefix("1.1.0.0/16"), VirtualNetworkID: "vpc-1"},
	}, nil)
	instances := NewInstancesManager(hivetest.Logger(t), api)

	m := ipamTypes.NewInstanceMap()
	m.Update(instanceID, ipamTypes.InterfaceRevision{Resource: iface.DeepCopy()})
	api.UpdateInstances(m)
	instances.mutex.Lock()
	instances.instances = m
	instances.mutex.Unlock()

	usedAlloc := ipamTypes.AllocationMap{}
	for ip := range used {
		usedAlloc[ip] = ipamTypes.AllocationIP{}
	}

	n := &Node{
		k8sObj: &v2.CiliumNode{
			ObjectMeta: metav1.ObjectMeta{Name: "node1"},
			Spec: v2.NodeSpec{
				InstanceID: instanceID,
				Azure:      types.AzureSpec{InterfaceName: requiredIfaceName},
			},
			Status: v2.NodeStatus{
				IPAM: ipamTypes.IPAMStatus{Used: usedAlloc},
			},
		},
		node:    fakeNodeActions(instanceID),
		manager: instances,
	}
	return n, api
}

func TestPrepareIPRelease_SelectsFreeIPs(t *testing.T) {
	iface := newAzureInterface(t, testVMSSIfaceID, "eth0", []string{"1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4"})
	used := map[string]struct{}{"1.1.1.1": {}, "1.1.1.2": {}}

	n, _ := newReleaseTestNode(t, testVMSSInstanceID, iface, "", used)
	r := n.PrepareIPRelease(2, hivetest.Logger(t))

	require.NotNil(t, r)
	require.Equal(t, testVMSSIfaceID, r.InterfaceID)
	require.Equal(t, ipamTypes.PoolID("subnet-1"), r.PoolID)
	require.ElementsMatch(t, []string{"1.1.1.3", "1.1.1.4"}, r.IPsToRelease)
}

func TestPrepareIPRelease_RespectsExcessLimit(t *testing.T) {
	iface := newAzureInterface(t, testVMSSIfaceID, "eth0", []string{"1.1.1.1", "1.1.1.2", "1.1.1.3"})

	n, _ := newReleaseTestNode(t, testVMSSInstanceID, iface, "", nil)
	r := n.PrepareIPRelease(1, hivetest.Logger(t))

	require.Len(t, r.IPsToRelease, 1)
}

func TestPrepareIPRelease_EmptyWhenAllUsed(t *testing.T) {
	iface := newAzureInterface(t, testVMSSIfaceID, "eth0", []string{"1.1.1.1", "1.1.1.2"})
	used := map[string]struct{}{"1.1.1.1": {}, "1.1.1.2": {}}

	n, _ := newReleaseTestNode(t, testVMSSInstanceID, iface, "", used)
	r := n.PrepareIPRelease(2, hivetest.Logger(t))

	require.Empty(t, r.IPsToRelease)
}

func TestPrepareIPRelease_RequiredIfaceName(t *testing.T) {
	iface := newAzureInterface(t, testVMSSIfaceID, "eth0", []string{"1.1.1.1", "1.1.1.2"})

	n, _ := newReleaseTestNode(t, testVMSSInstanceID, iface, "eth1", nil)
	r := n.PrepareIPRelease(2, hivetest.Logger(t))

	require.Empty(t, r.IPsToRelease)
}

func TestReleaseIPs_NoOpWhenEmpty(t *testing.T) {
	iface := newAzureInterface(t, testVMSSIfaceID, "eth0", []string{"1.1.1.1"})
	n, _ := newReleaseTestNode(t, testVMSSInstanceID, iface, "", nil)

	require.NoError(t, n.ReleaseIPs(t.Context(), &ipam.ReleaseAction{}))
}

func TestReleaseIPs_VMSSPath(t *testing.T) {
	iface := newAzureInterface(t, testVMSSIfaceID, "eth0", []string{"1.1.1.1", "1.1.1.2", "1.1.1.3"})

	n, _ := newReleaseTestNode(t, testVMSSInstanceID, iface, "", nil)
	require.Equal(t, "vmss11", iface.GetVMScaleSetName())

	err := n.ReleaseIPs(t.Context(), &ipam.ReleaseAction{
		InterfaceID:  testVMSSIfaceID,
		PoolID:       "subnet-1",
		IPsToRelease: []string{"1.1.1.2", "1.1.1.3"},
	})
	require.NoError(t, err)

	got, err := n.manager.api.GetInstance(t.Context(), nil, testVMSSInstanceID)
	require.NoError(t, err)
	for _, ifaceObj := range got.Interfaces {
		az := ifaceObj.Resource.(*types.AzureInterface)
		ips := make([]string, 0, len(az.Addresses))
		for _, a := range az.Addresses {
			ips = append(ips, a.IP)
		}
		require.ElementsMatch(t, []string{"1.1.1.1"}, ips)
	}
}

func TestReleaseIPs_VMPath(t *testing.T) {
	iface := newAzureInterface(t, testVMIfaceID, "eth0", []string{"1.1.1.1", "1.1.1.2"})

	n, _ := newReleaseTestNode(t, testVMInstanceID, iface, "", nil)
	require.Empty(t, iface.GetVMScaleSetName())

	err := n.ReleaseIPs(t.Context(), &ipam.ReleaseAction{
		InterfaceID:  testVMIfaceID,
		PoolID:       "subnet-1",
		IPsToRelease: []string{"1.1.1.2"},
	})
	require.NoError(t, err)
}

func TestReleaseIPs_InterfaceNotFound(t *testing.T) {
	iface := newAzureInterface(t, testVMSSIfaceID, "eth0", []string{"1.1.1.1"})
	n, _ := newReleaseTestNode(t, testVMSSInstanceID, iface, "", nil)

	err := n.ReleaseIPs(t.Context(), &ipam.ReleaseAction{
		InterfaceID:  "missing",
		IPsToRelease: []string{"1.1.1.1"},
	})
	require.Error(t, err)
}
