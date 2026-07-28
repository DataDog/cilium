// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/azure/types"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func TestGetMaximumAllocatableIPv4(t *testing.T) {
	n := &Node{}
	require.Equal(t, types.InterfaceAddressLimit, n.GetMaximumAllocatableIPv4())
}

const statusTestIDFormat = "/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss1/virtualMachines/0/networkInterfaces/%s"

// PopulateStatusFields compares every AzureAddress field to keep the address
// sort a total order.
func TestAzureAddressFullyCompared(t *testing.T) {
	require.Equal(t, 3, reflect.TypeFor[types.AzureAddress]().NumField(),
		"AzureAddress gained a field; extend the address comparator in PopulateStatusFields")
}

// Addresses share an IP so the comparator's Subnet and State tie-breakers each
// decide an ordering, and SecurityGroup collates inversely to ID so sorting by
// the wrong field is visible.
func newStatusTestInterfaces() []*types.AzureInterface {
	return newStatusTestInterfacesWith([]types.AzureAddress{
		{IP: "10.0.0.2", Subnet: "s-1", State: types.StateSucceeded},
		{IP: "10.0.0.1", Subnet: "s-2", State: types.StateSucceeded},
		{IP: "10.0.0.1", Subnet: "s-1", State: types.StateSucceeded},
		{IP: "10.0.0.1", Subnet: "s-1", State: "failed"},
	})
}

func newStatusTestInterfacesWith(addresses []types.AzureAddress) []*types.AzureInterface {
	names := []string{"nic-c", "nic-a", "nic-b"}
	var ifaces []*types.AzureInterface
	for i, name := range names {
		ifaces = append(ifaces, &types.AzureInterface{
			ID:            fmt.Sprintf(statusTestIDFormat, name),
			SecurityGroup: fmt.Sprintf("sg-%d", len(names)-i),
			Addresses:     addresses,
		})
	}
	return ifaces
}

func statusTestIDs(names ...string) []string {
	ids := make([]string, 0, len(names))
	for _, name := range names {
		ids = append(ids, fmt.Sprintf(statusTestIDFormat, name))
	}
	return ids
}

func newStatusTestNode(ifaces []*types.AzureInterface) *Node {
	m := ipamTypes.NewInstanceMap()
	for _, iface := range ifaces {
		m.Update("vm1", ipamTypes.InterfaceRevision{Resource: iface.DeepCopy()})
	}
	return &Node{
		node:    mockIPAMNode("vm1"),
		manager: &InstancesManager{instances: m},
	}
}

// Repeated calls must produce an identical status, and it must match the copy
// the operator reads back from the apiserver, or
// ciliumNodeUpdateImplementation.UpdateStatus writes /status on every sync.
func TestPopulateStatusFieldsDeterministicOrder(t *testing.T) {
	node := newStatusTestNode(newStatusTestInterfaces())

	fromAPIServer := &v2.CiliumNode{}
	node.PopulateStatusFields(fromAPIServer)
	marshalled, err := json.Marshal(fromAPIServer)
	require.NoError(t, err)
	fromAPIServer = &v2.CiliumNode{}
	require.NoError(t, json.Unmarshal(marshalled, fromAPIServer))

	// ForeachInterface's map iteration order is randomized per call.
	for i := range 10 {
		k8sObj := &v2.CiliumNode{}
		node.PopulateStatusFields(k8sObj)

		got := k8sObj.Status.Azure.Interfaces
		ids := make([]string, 0, len(got))
		for _, iface := range got {
			ids = append(ids, iface.ID)

			addrs := make([]string, 0, len(iface.Addresses))
			for _, addr := range iface.Addresses {
				addrs = append(addrs, fmt.Sprintf("%s/%s/%s", addr.IP, addr.Subnet, addr.State))
			}
			require.Equal(t, []string{
				"10.0.0.1/s-1/failed",
				"10.0.0.1/s-1/" + types.StateSucceeded,
				"10.0.0.1/s-2/" + types.StateSucceeded,
				"10.0.0.2/s-1/" + types.StateSucceeded,
			}, addrs, "iteration %d: addresses not in total order", i)
		}
		require.Equal(t, statusTestIDs("nic-a", "nic-b", "nic-c"), ids, "iteration %d", i)

		require.True(t, fromAPIServer.Status.DeepEqual(&k8sObj.Status),
			"iteration %d: no-op sync differs from the apiserver copy, forcing a /status write", i)
	}
}

// Azure does not document an order for an interface's IP configurations, so a
// reordered poll must still produce the same status.
func TestPopulateStatusFieldsAddressOrderIndependent(t *testing.T) {
	addresses := []types.AzureAddress{
		{IP: "10.0.0.1", Subnet: "s-1", State: types.StateSucceeded},
		{IP: "10.0.0.2", Subnet: "s-1", State: types.StateSucceeded},
		{IP: "10.0.0.3", Subnet: "s-1", State: types.StateSucceeded},
	}
	reordered := []types.AzureAddress{addresses[2], addresses[0], addresses[1]}

	first := &v2.CiliumNode{}
	newStatusTestNode(newStatusTestInterfacesWith(addresses)).PopulateStatusFields(first)

	second := &v2.CiliumNode{}
	newStatusTestNode(newStatusTestInterfacesWith(reordered)).PopulateStatusFields(second)

	require.True(t, first.Status.DeepEqual(&second.Status))
}

func TestPopulateStatusFieldsReplacesStaleInterfaces(t *testing.T) {
	node := newStatusTestNode(newStatusTestInterfaces())

	k8sObj := &v2.CiliumNode{}
	k8sObj.Status.Azure.Interfaces = []types.AzureInterface{{ID: "detached"}}
	node.PopulateStatusFields(k8sObj)

	ids := make([]string, 0, len(k8sObj.Status.Azure.Interfaces))
	for _, iface := range k8sObj.Status.Azure.Interfaces {
		ids = append(ids, iface.ID)
	}
	require.Equal(t, statusTestIDs("nic-a", "nic-b", "nic-c"), ids)
}

// The status is sorted in place, so it must be built from copies: the instance
// cache is shared across nodes and read under a read lock.
func TestPopulateStatusFieldsDoesNotMutateInstances(t *testing.T) {
	node := newStatusTestNode(newStatusTestInterfaces())

	before := map[string]*types.AzureInterface{}
	node.manager.instances.ForeachInterface("vm1", func(_, interfaceID string, obj ipamTypes.InterfaceRevision) error {
		before[interfaceID] = obj.Resource.(*types.AzureInterface).DeepCopy()
		return nil
	})
	require.NotEmpty(t, before)

	node.PopulateStatusFields(&v2.CiliumNode{})

	node.manager.instances.ForeachInterface("vm1", func(_, interfaceID string, obj ipamTypes.InterfaceRevision) error {
		require.True(t, before[interfaceID].DeepEqual(obj.Resource.(*types.AzureInterface)),
			"cached interface %s mutated by PopulateStatusFields", interfaceID)
		return nil
	})
}

// An empty status is the common bootstrap shape, and it must round trip too:
// omitempty drops the slice, so the apiserver copy reads back as nil.
func TestPopulateStatusFieldsNoInterfaces(t *testing.T) {
	for name, ifaces := range map[string][]*types.AzureInterface{
		"no interfaces": nil,
		"no addresses":  newStatusTestInterfacesWith(nil),
	} {
		t.Run(name, func(t *testing.T) {
			node := newStatusTestNode(ifaces)

			k8sObj := &v2.CiliumNode{}
			node.PopulateStatusFields(k8sObj)

			marshalled, err := json.Marshal(k8sObj)
			require.NoError(t, err)
			fromAPIServer := &v2.CiliumNode{}
			require.NoError(t, json.Unmarshal(marshalled, fromAPIServer))

			require.True(t, fromAPIServer.Status.DeepEqual(&k8sObj.Status))
		})
	}
}
