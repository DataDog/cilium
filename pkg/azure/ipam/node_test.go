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

// TestPopulateStatusFieldsDeterministicOrder ensures that repeated calls to
// PopulateStatusFields produce a byte-for-byte identical (DeepEqual)
// Status.Azure.Interfaces slice, sorted by interface ID, regardless of the
// randomized map-iteration order of ForeachInterface. Without this, the
// operator's DeepEqual-based write-skip gate cannot suppress no-op
// CiliumNode /status writes, reintroducing the per-tick spurious write bug
// this test guards against.
func TestPopulateStatusFieldsDeterministicOrder(t *testing.T) {
	api := apimock.NewAPI(nil, nil)
	require.NotNil(t, api)

	mngr := NewInstancesManager(hivetest.Logger(t), api)
	require.NotNil(t, mngr)

	instances := ipamTypes.NewInstanceMap()
	for _, id := range []string{"intf-c", "intf-a", "intf-b"} {
		iface := &types.AzureInterface{
			SecurityGroup: "sg-" + id,
		}
		iface.SetID(id)
		instances.Update("i-1", ipamTypes.InterfaceRevision{
			Resource: iface.DeepCopy(),
		})
	}
	api.UpdateInstances(instances)
	require.False(t, mngr.Resync(t.Context()).IsZero())

	node := &Node{
		node:    fakeNodeActions{instanceID: "i-1"},
		manager: mngr,
	}

	var results [][]types.AzureInterface
	for i := 0; i < 10; i++ {
		k8sObj := &v2.CiliumNode{}
		node.PopulateStatusFields(k8sObj)
		results = append(results, k8sObj.Status.Azure.Interfaces)
	}

	for i, ifaces := range results {
		require.Len(t, ifaces, 3, "iteration %d", i)
		require.True(t, ifaces[0].ID < ifaces[1].ID && ifaces[1].ID < ifaces[2].ID,
			"iteration %d: interfaces not sorted by ID: %v", i, []string{ifaces[0].ID, ifaces[1].ID, ifaces[2].ID})
		if i > 0 {
			require.Equal(t, results[0], ifaces, "iteration %d produced a different order than iteration 0", i)
		}
	}
}

// TestPopulateStatusFieldsDeepEqualAcrossShuffledOrders ties the ordering
// fix directly to the actual write-skip gate it exists to fix: the
// operator's origNode.Status.DeepEqual(&node.Status) call in
// operator/cmd/cilium_node.go. TestPopulateStatusFieldsDeterministicOrder
// only checks slice order via reflect-based require.Equal on hand-built
// interfaces with empty vmssName/vmID/resourceGroup; this test instead uses
// real VMSS-style resource IDs (so those unexported fields are actually
// populated by SetID/extractIDs, not empty) and asserts NodeStatus.DeepEqual
// -- the real consumer -- reports no difference across repeated,
// independently-randomized calls to PopulateStatusFields.
func TestPopulateStatusFieldsDeepEqualAcrossShuffledOrders(t *testing.T) {
	api := apimock.NewAPI(nil, nil)
	require.NotNil(t, api)

	mngr := NewInstancesManager(hivetest.Logger(t), api)
	require.NotNil(t, mngr)

	instances := ipamTypes.NewInstanceMap()
	resourceIDs := []string{
		"/subscriptions/xxx/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss1/virtualMachines/0/networkInterfaces/intf-a",
		"/subscriptions/xxx/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss1/virtualMachines/1/networkInterfaces/intf-b",
		"/subscriptions/xxx/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss1/virtualMachines/2/networkInterfaces/intf-c",
	}
	for _, id := range resourceIDs {
		iface := &types.AzureInterface{CIDR: "10.0.0.0/24"}
		iface.SetID(id)
		instances.Update("i-1", ipamTypes.InterfaceRevision{
			Resource: iface.DeepCopy(),
		})
	}
	api.UpdateInstances(instances)
	require.False(t, mngr.Resync(t.Context()).IsZero())

	node := &Node{
		node:    fakeNodeActions{instanceID: "i-1"},
		manager: mngr,
	}

	var reference *v2.CiliumNode
	for i := 0; i < 20; i++ {
		k8sObj := &v2.CiliumNode{}
		node.PopulateStatusFields(k8sObj)
		require.Len(t, k8sObj.Status.Azure.Interfaces, len(resourceIDs), "iteration %d", i)
		for _, iface := range k8sObj.Status.Azure.Interfaces {
			// Confirm the unexported, json:"-" fields are actually
			// populated (non-empty) for this test, unlike
			// TestPopulateStatusFieldsDeterministicOrder's bare interfaces.
			require.NotEmpty(t, iface.GetVMScaleSetName(), "iteration %d", i)
			require.NotEmpty(t, iface.GetVMID(), "iteration %d", i)
			require.NotEmpty(t, iface.GetResourceGroup(), "iteration %d", i)
		}
		if reference == nil {
			reference = k8sObj
			continue
		}
		require.True(t, reference.Status.DeepEqual(&k8sObj.Status),
			"iteration %d: NodeStatus.DeepEqual reported a difference despite identical underlying Azure interfaces", i)
	}
}

type fakeNodeActions struct {
	instanceID string
}

func (f fakeNodeActions) InstanceID() string {
	return f.instanceID
}
