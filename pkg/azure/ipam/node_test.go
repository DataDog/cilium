// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	apimock "github.com/cilium/cilium/pkg/azure/api/mock"
	"github.com/cilium/cilium/pkg/azure/types"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func TestGetMaximumAllocatableIPv4(t *testing.T) {
	n := &Node{}
	require.Equal(t, types.InterfaceAddressLimit, n.GetMaximumAllocatableIPv4())
}

// mockPDNode is a configurable ipamNodeActions used by prefix-delegation tests.
type mockPDNode struct {
	instanceID string
	pdEnabled  bool
}

func (m mockPDNode) InstanceID() string              { return m.instanceID }
func (m mockPDNode) IsPrefixDelegationEnabled() bool { return m.pdEnabled }

func newPDTestNode(t *testing.T, instanceID string, pdEnabled bool, ifaces ...*types.AzureInterface) *Node {
	t.Helper()
	api := apimock.NewAPI(nil, nil)
	mngr := NewInstancesManager(hivetest.Logger(t), api)
	if len(ifaces) > 0 {
		instances := ipamTypes.NewInstanceMap()
		for _, iface := range ifaces {
			instances.Update(instanceID, ipamTypes.InterfaceRevision{Resource: iface.DeepCopy()})
		}
		mngr.instances = instances
	}
	return &Node{
		k8sObj:  &v2.CiliumNode{Spec: v2.NodeSpec{Azure: types.AzureSpec{}}},
		node:    mockPDNode{instanceID: instanceID, pdEnabled: pdEnabled},
		manager: mngr,
	}
}

func TestIsPrefixDelegated(t *testing.T) {
	const instanceID = "vm-test"

	mkPrefixIface := func() *types.AzureInterface {
		iface := &types.AzureInterface{Name: "eth0"}
		iface.SetID("/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/eth0")
		iface.Prefixes = []string{"10.0.0.0/28"}
		for i := 0; i < 16; i++ {
			iface.Addresses = append(iface.Addresses, types.AzureAddress{
				IP:     "10.0.0.0",
				Subnet: "subnet-1",
				State:  types.StateSucceeded,
			})
		}
		return iface
	}
	mkSecondaryIface := func() *types.AzureInterface {
		iface := &types.AzureInterface{Name: "eth0"}
		iface.SetID("/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/eth0")
		iface.Addresses = []types.AzureAddress{
			{IP: "10.0.0.10", Subnet: "subnet-1", State: types.StateSucceeded},
		}
		return iface
	}
	mkEmptyIface := func() *types.AzureInterface {
		iface := &types.AzureInterface{Name: "eth0"}
		iface.SetID("/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/eth0")
		return iface
	}

	t.Run("flag off", func(t *testing.T) {
		n := newPDTestNode(t, instanceID, false, mkEmptyIface())
		require.False(t, n.IsPrefixDelegated())
	})

	t.Run("flag on, no interfaces yet", func(t *testing.T) {
		n := newPDTestNode(t, instanceID, true)
		require.True(t, n.IsPrefixDelegated())
	})

	t.Run("flag on, only prefix-derived addresses", func(t *testing.T) {
		n := newPDTestNode(t, instanceID, true, mkPrefixIface())
		require.True(t, n.IsPrefixDelegated())
	})

	t.Run("flag on, per-node opt-out", func(t *testing.T) {
		n := newPDTestNode(t, instanceID, true, mkEmptyIface())
		disable := true
		n.k8sObj.Spec.Azure.DisablePrefixDelegation = &disable
		require.False(t, n.IsPrefixDelegated())
	})

	t.Run("flag on, mixed mode rejected", func(t *testing.T) {
		n := newPDTestNode(t, instanceID, true, mkSecondaryIface())
		require.False(t, n.IsPrefixDelegated())
	})
}

func TestIsSubnetAtPrefixCapacity(t *testing.T) {
	require.False(t, isSubnetAtPrefixCapacity(nil))
	require.False(t, isSubnetAtPrefixCapacity(errString("something else went wrong")))
	require.True(t, isSubnetAtPrefixCapacity(errString("PUT failed: NoAvailableIPAddressesInSubnet")))
	require.True(t, isSubnetAtPrefixCapacity(errString("SubnetIsFull, cannot allocate")))
	require.True(t, isSubnetAtPrefixCapacity(errString("InsufficientCidrBlocks for /28")))
	require.True(t, isSubnetAtPrefixCapacity(errString("PrefixUnavailable in subnet")))
}

type errString string

func (e errString) Error() string { return string(e) }
