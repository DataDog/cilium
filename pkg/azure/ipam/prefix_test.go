// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	metricsmock "github.com/cilium/cilium/operator/pkg/ipam/metrics/mock"
	"github.com/cilium/cilium/operator/pkg/ipam/nodemanager"
	apimock "github.com/cilium/cilium/pkg/azure/api/mock"
	"github.com/cilium/cilium/pkg/azure/types"
	iputil "github.com/cilium/cilium/pkg/ip"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/testutils"
)

const (
	prefixTestVMID    = "/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm1"
	prefixTestIfaceID = prefixTestVMID + "/networkInterfaces/nic1"
)

type prefixFixture struct {
	api       *apimock.API
	instances *InstancesManager
	mngr      *nodemanager.NodeManager
	k8s       *k8sMock
	metrics   interface{ IPAllocations(subnetID string) int64 }
}

func newPrefixTestInterface(name, id, primaryIP string, secondaryIPs ...string) *types.AzureInterface {
	iface := newCapacityTestInterface(name, id, primaryIP, secondaryIPs...)
	iface.Subnet.ID = testSubnet.ID
	return iface
}

func newPrefixFixture(t *testing.T, subnets []*ipamTypes.Subnet, usePrimary, prefixDelegation bool, ifaces ...*types.AzureInterface) *prefixFixture {
	t.Helper()
	api := apimock.NewAPI(subnets)
	m := ipamTypes.NewInstanceMap()
	for _, iface := range ifaces {
		m.Update(prefixTestVMID, iface.DeepCopy())
	}
	api.UpdateInstances(m)
	api.ReserveInstanceAddresses()

	instances := NewInstancesManager(hivetest.Logger(t), api, usePrimary)
	_, err := instances.Resync(t.Context())
	require.NoError(t, err)

	metrics := metricsmock.NewMockMetrics()
	k8s := newK8sMock()
	mngr, err := nodemanager.NewNodeManager(hivetest.Logger(t), instances, k8s, metrics, 10, false, 0, prefixDelegation)
	require.NoError(t, err)
	return &prefixFixture{api: api, instances: instances, mngr: mngr, k8s: k8s, metrics: metrics}
}

func (f *prefixFixture) upsert(t *testing.T, preAllocate int, disablePrefixDelegation *bool) {
	t.Helper()
	cn := newCiliumNode("node1", prefixTestVMID, preAllocate, 0)
	cn.Spec.Azure.DisablePrefixDelegation = disablePrefixDelegation
	f.mngr.Upsert(cn)
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(f.mngr, "node1", 0) }, 5*time.Second))
}

// register adds the node without letting the node manager allocate on its
// own, for tests that allocate step by step.
func (f *prefixFixture) register(t *testing.T, interfaceName string) {
	t.Helper()
	cn := newCiliumNode("node1", prefixTestVMID, -1, 0)
	cn.Spec.Azure.InterfaceName = interfaceName
	cn.Spec.Azure.DisablePrefixDelegation = new(false)
	f.mngr.Upsert(cn)
}

func (f *prefixFixture) node(t *testing.T) *Node {
	t.Helper()
	node := f.mngr.Get("node1")
	require.NotNil(t, node)
	return node.Ops().(*Node)
}

func (f *prefixFixture) iface(t *testing.T, id string) *types.AzureInterface {
	t.Helper()
	nics, err := f.api.ListVMNetworkInterfaces(t.Context(), prefixTestVMID)
	require.NoError(t, err)
	iface, ok := f.api.ParseInterfacesIntoInstance(nics, nil).Interfaces[id]
	require.True(t, ok)
	return iface.(*types.AzureInterface)
}

// allocate runs one allocation for count addresses, as the generic node
// manager does, and refreshes the instance cache.
func (f *prefixFixture) allocate(t *testing.T, count int) (int, error) {
	t.Helper()
	n := f.node(t)
	a, err := n.PrepareIPAllocation(hivetest.Logger(t))
	require.NoError(t, err)
	require.NotEmpty(t, a.InterfaceID)
	a.IPv4.AvailableForAllocation = min(a.IPv4.AvailableForAllocation, count)
	err = n.AllocateIPs(t.Context(), a)
	_, resyncErr := f.instances.Resync(t.Context())
	require.NoError(t, resyncErr)
	return a.IPv4.AvailableForAllocation, err
}

func TestPrefixDelegationAllocatesPrefixes(t *testing.T) {
	f := newPrefixFixture(t, []*ipamTypes.Subnet{testSubnet}, false, true,
		newPrefixTestInterface("eth0", prefixTestIfaceID, "1.1.0.4"))
	f.upsert(t, 20, new(false))

	iface := f.iface(t, prefixTestIfaceID)
	require.Len(t, iface.Prefixes, 2)
	require.Empty(t, iface.Addresses)
	require.Equal(t, 2*types.PrefixSizeIPv4, f.mngr.Get("node1").Stats().IPv4.AvailableIPs)
	require.EqualValues(t, 2*types.PrefixSizeIPv4, f.metrics.IPAllocations(testSubnet.ID))
	require.True(t, f.node(t).IsPrefixDelegated())

	require.NoError(t, testutils.WaitUntil(func() bool {
		cn := f.k8s.getLatestNode("node1")
		return cn != nil && len(cn.Status.Azure.Interfaces) == 1 && len(cn.Status.Azure.Interfaces[0].Prefixes) == 2
	}, 5*time.Second))
}

func TestPrefixDelegationAllocatesAddressesWithoutPrefixDelegation(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		prefixDelegation        bool
		disablePrefixDelegation *bool
	}{
		{name: "operator flag off", disablePrefixDelegation: new(false)},
		{name: "agent without prefix support", prefixDelegation: true},
		{name: "agent opted out", prefixDelegation: true, disablePrefixDelegation: new(true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			iface := newPrefixTestInterface("eth0", prefixTestIfaceID, "1.1.0.4")
			iface.Prefixes = []types.AzurePrefix{
				{CIDR: iputil.PrefixFrom(netip.MustParsePrefix("1.1.1.16/28")), State: types.StateSucceeded},
			}
			f := newPrefixFixture(t, []*ipamTypes.Subnet{testSubnet}, false, tc.prefixDelegation, iface)
			f.upsert(t, 20, tc.disablePrefixDelegation)

			iface = f.iface(t, prefixTestIfaceID)
			require.Len(t, iface.Prefixes, 1)
			require.Zero(t, f.api.PrefixRequests())
			wantAddresses := 20
			if tc.disablePrefixDelegation != nil {
				// The agent consumes the existing prefix.
				wantAddresses -= types.PrefixSizeIPv4
			}
			require.Len(t, iface.Addresses, wantAddresses)
			require.False(t, f.node(t).IsPrefixDelegated())
		})
	}
}

func TestPrefixDelegationMixedInterfaces(t *testing.T) {
	t.Run("secondary address allocates addresses", func(t *testing.T) {
		f := newPrefixFixture(t, []*ipamTypes.Subnet{testSubnet}, false, true,
			newPrefixTestInterface("eth0", prefixTestIfaceID, "1.1.0.4", "1.1.0.5"))
		f.upsert(t, 8, new(false))

		iface := f.iface(t, prefixTestIfaceID)
		require.Empty(t, iface.Prefixes)
		require.Len(t, iface.Addresses, 8)
		require.Zero(t, f.api.PrefixRequests())
	})

	t.Run("exposed primary allocates prefixes", func(t *testing.T) {
		f := newPrefixFixture(t, []*ipamTypes.Subnet{testSubnet}, true, true,
			newPrefixTestInterface("eth0", prefixTestIfaceID, "1.1.0.4", "1.1.0.4"))
		f.upsert(t, 8, new(false))

		iface := f.iface(t, prefixTestIfaceID)
		require.Len(t, iface.Prefixes, 1)
		require.Len(t, iface.Addresses, 1)
	})

	for _, tc := range []struct {
		name        string
		secondaries []string
		want        bool
	}{
		{name: "unselected interface with a secondary address", secondaries: []string{"1.1.0.9"}, want: false},
		{name: "unselected interface with only its primary", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPrefixFixture(t, []*ipamTypes.Subnet{testSubnet}, false, true,
				newPrefixTestInterface("eth0", prefixTestIfaceID, "1.1.0.4"),
				newPrefixTestInterface("eth1", prefixTestVMID+"/networkInterfaces/nic2", "1.1.0.8", tc.secondaries...))
			f.register(t, "eth0")

			require.Equal(t, tc.want, f.node(t).IsPrefixDelegated())
		})
	}
}

func TestPrefixDelegationFallsBackToAddresses(t *testing.T) {
	iface := newPrefixTestInterface("eth0", prefixTestIfaceID, "1.1.0.4")
	iface.Prefixes = []types.AzurePrefix{
		{CIDR: iputil.PrefixFrom(netip.MustParsePrefix("1.1.1.16/28")), State: types.StateSucceeded},
	}
	f := newPrefixFixture(t, []*ipamTypes.Subnet{testSubnet}, false, true, iface)
	f.api.SetPrefixError(fmt.Errorf("wrapped: %w", apimock.SubnetIsFullError()))
	f.register(t, "")

	assigned, err := f.allocate(t, 4)
	require.NoError(t, err)
	require.Equal(t, 4, assigned)
	require.Equal(t, 1, f.api.PrefixRequests())
	iface = f.iface(t, prefixTestIfaceID)
	require.Len(t, iface.Prefixes, 1)
	require.Len(t, iface.Addresses, 4)

	// The interface still holds prefixes, so the next allocation tries one
	// again.
	f.api.SetPrefixError(nil)
	assigned, err = f.allocate(t, 4)
	require.NoError(t, err)
	require.Equal(t, types.PrefixSizeIPv4, assigned)
	require.Equal(t, 2, f.api.PrefixRequests())
	iface = f.iface(t, prefixTestIfaceID)
	require.Len(t, iface.Prefixes, 2)
	require.Len(t, iface.Addresses, 4)
}

func TestPrefixDelegationFallbackLimitedBySlots(t *testing.T) {
	f := newPrefixFixture(t, []*ipamTypes.Subnet{testSubnet}, false, true,
		withCapacityTestPrefixes(newPrefixTestInterface("eth0", prefixTestIfaceID, "1.1.0.4"),
			types.StateSucceeded, capacityTestPrefixes("1.1.16.0/28", 254)...))
	f.api.SetPrefixError(apimock.SubnetIsFullError())
	f.register(t, "")

	assigned, err := f.allocate(t, 4)
	require.NoError(t, err)
	require.Equal(t, 1, assigned)
	iface := f.iface(t, prefixTestIfaceID)
	require.Len(t, iface.Prefixes, 254)
	require.Len(t, iface.Addresses, 1)
}

func TestPrefixDelegationFallbackOnPrefixFreeInterface(t *testing.T) {
	f := newPrefixFixture(t, []*ipamTypes.Subnet{testSubnet}, false, true,
		newPrefixTestInterface("eth0", prefixTestIfaceID, "1.1.0.4"))
	f.api.SetPrefixError(apimock.SubnetIsFullError())
	f.register(t, "")

	assigned, err := f.allocate(t, 8)
	require.NoError(t, err)
	require.Equal(t, 8, assigned)
	require.Equal(t, 1, f.api.PrefixRequests())

	// The interface now holds addresses without prefixes.
	f.api.SetPrefixError(nil)
	require.False(t, f.node(t).IsPrefixDelegated())
	_, err = f.allocate(t, 8)
	require.NoError(t, err)
	require.Equal(t, 1, f.api.PrefixRequests())

	iface := f.iface(t, prefixTestIfaceID)
	require.Empty(t, iface.Prefixes)
	addrs := make([]netip.Addr, 0, len(iface.Addresses))
	for _, address := range iface.Addresses {
		addrs = append(addrs, address.IP.Addr)
	}
	require.Len(t, addrs, 16)
	require.NoError(t, f.api.UnassignPrivateIpAddressesVMSS(t.Context(), "vm1", "vmss11", "eth0", addrs))
	_, err = f.instances.Resync(t.Context())
	require.NoError(t, err)

	require.True(t, f.node(t).IsPrefixDelegated())
	assigned, err = f.allocate(t, 8)
	require.NoError(t, err)
	require.Equal(t, types.PrefixSizeIPv4, assigned)
	require.Equal(t, 2, f.api.PrefixRequests())
}

func TestPrefixDelegationHalvesOnSubnetFull(t *testing.T) {
	subnet := &ipamTypes.Subnet{ID: testSubnet.ID, VirtualNetworkID: "vpc-1", CIDR: netip.MustParsePrefix("1.1.0.0/29")}
	iface := newPrefixTestInterface("eth0", prefixTestIfaceID, "1.1.0.4")
	f := newPrefixFixture(t, []*ipamTypes.Subnet{subnet}, false, true, iface)
	// The primary and another instance take 3 of the subnet's 6 addresses;
	// many more are reported free.
	vm2ID := "/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm2"
	m := ipamTypes.NewInstanceMap()
	m.Update(prefixTestVMID, iface.DeepCopy())
	m.Update(vm2ID, newPrefixTestInterface("eth0", vm2ID+"/networkInterfaces/nic1", "1.1.0.8"))
	f.api.UpdateInstances(m)
	f.api.ReserveInstanceAddresses()
	require.NoError(t, f.api.AssignPrivateIpAddressesVMSS(t.Context(), "vm2", "vmss11", testSubnet.ID, "eth0", 2, 0))
	f.api.SetReportedAvailableAddresses(testSubnet.ID, 123)
	_, err := f.instances.Resync(t.Context())
	require.NoError(t, err)

	f.register(t, "eth0")

	// The prefix fails, then 8 and 4 addresses, then 2 succeed.
	assigned, err := f.allocate(t, 8)
	require.NoError(t, err)
	require.Equal(t, 2, assigned)
	require.Equal(t, 1, f.api.PrefixRequests())

	assigned, err = f.allocate(t, 6)
	require.NoError(t, err)
	require.Equal(t, 1, assigned)

	_, err = f.allocate(t, 5)
	require.Error(t, err)
	require.Len(t, f.iface(t, prefixTestIfaceID).Addresses, 3)
}

func TestPrefixDelegationHalvingRecordsAllocations(t *testing.T) {
	subnet := &ipamTypes.Subnet{ID: testSubnet.ID, VirtualNetworkID: "vpc-1", CIDR: netip.MustParsePrefix("1.1.0.0/29")}
	f := newPrefixFixture(t, []*ipamTypes.Subnet{subnet}, false, true,
		newPrefixTestInterface("eth0", prefixTestIfaceID, "1.1.0.4"))
	f.api.SetReportedAvailableAddresses(testSubnet.ID, 123)
	_, err := f.instances.Resync(t.Context())
	require.NoError(t, err)

	// 5 addresses are free: 4 are assigned after halving from 8, then the
	// last one after halving from 4.
	cn := newCiliumNode("node1", prefixTestVMID, 8, 0)
	cn.Spec.Azure.DisablePrefixDelegation = new(false)
	f.mngr.Upsert(cn)
	require.NoError(t, testutils.WaitUntil(func() bool { return f.metrics.IPAllocations(testSubnet.ID) == 5 }, 5*time.Second))
	require.Len(t, f.iface(t, prefixTestIfaceID).Addresses, 5)
}

func TestPrefixDelegationReturnsOtherPrefixErrors(t *testing.T) {
	f := newPrefixFixture(t, []*ipamTypes.Subnet{testSubnet}, false, true,
		newPrefixTestInterface("eth0", prefixTestIfaceID, "1.1.0.4"))
	f.api.SetPrefixError(&azcore.ResponseError{ErrorCode: "AuthorizationFailed"})
	f.register(t, "")

	_, err := f.allocate(t, 8)
	require.ErrorContains(t, err, "AuthorizationFailed")
	iface := f.iface(t, prefixTestIfaceID)
	require.Empty(t, iface.Prefixes)
	require.Empty(t, iface.Addresses)
}

func TestIsSubnetOutOfPrefixes(t *testing.T) {
	require.True(t, isSubnetOutOfPrefixes(fmt.Errorf("error while waiting for virtualMachineScaleSetVMs Update to complete: %w", apimock.SubnetIsFullError())))
	require.False(t, isSubnetOutOfPrefixes(fmt.Errorf("wrapped: %w", &azcore.ResponseError{ErrorCode: "AuthorizationFailed"})))
	require.False(t, isSubnetOutOfPrefixes(fmt.Errorf("unrelated")))
}

func TestPrefixDelegationCapacity(t *testing.T) {
	f := newPrefixFixture(t, []*ipamTypes.Subnet{testSubnet}, false, true,
		newPrefixTestInterface("eth0", prefixTestIfaceID, "1.1.0.4"))
	f.register(t, "")

	n := f.node(t)
	require.Equal(t, 255*types.PrefixSizeIPv4, n.GetMaximumAllocatableIPv4())
	_, stats, err := n.ResyncInterfacesAndIPs(t.Context(), hivetest.Logger(t))
	require.NoError(t, err)
	require.Equal(t, 255*types.PrefixSizeIPv4, stats.NodeCapacity)
}

func TestPrefixDelegationFullSelectedInterface(t *testing.T) {
	f := newPrefixFixture(t, []*ipamTypes.Subnet{testSubnet}, false, true,
		withCapacityTestPrefixes(newPrefixTestInterface("eth0", prefixTestIfaceID, "1.1.0.4"),
			types.StateSucceeded, capacityTestPrefixes("1.1.16.0/28", 255)...),
		newPrefixTestInterface("eth1", prefixTestVMID+"/networkInterfaces/nic2", "1.1.0.8"))
	f.register(t, "eth0")

	a, err := f.node(t).PrepareIPAllocation(hivetest.Logger(t))
	require.NoError(t, err)
	require.Empty(t, a.InterfaceID)
	require.Zero(t, a.IPv4.AvailableForAllocation)
	require.Equal(t, 255*types.PrefixSizeIPv4, f.node(t).GetMaximumAllocatableIPv4())
}

func TestIsPrefixDelegatedWithQueuedWriter(t *testing.T) {
	f := newPrefixFixture(t, []*ipamTypes.Subnet{testSubnet}, false, true,
		newPrefixTestInterface("eth0", prefixTestIfaceID, "1.1.0.4"))
	f.register(t, "")
	n := f.node(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		n.manager.mutex.RLock()
		writer := make(chan struct{})
		go func() {
			n.manager.mutex.Lock()
			n.manager.mutex.Unlock()
			close(writer)
		}()
		time.Sleep(10 * time.Millisecond)
		n.isPrefixDelegatedLocked()
		n.addressesPerSlotLocked()
		n.manager.mutex.RUnlock()
		<-writer
		n.GetMaximumAllocatableIPv4()
		n.IsPrefixDelegated()
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("deadlock with a queued writer")
	}
}
