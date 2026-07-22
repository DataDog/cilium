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

// TestPopulateStatusFieldsDeterministicOrder verifies PopulateStatusFields
// sorts interfaces by ID so repeated calls are DeepEqual-stable regardless of
// the randomized map-iteration order of ForeachInterface.
func TestPopulateStatusFieldsDeterministicOrder(t *testing.T) {
	api := apimock.NewAPI(nil, nil)
	require.NotNil(t, api)

	mngr := NewInstancesManager(hivetest.Logger(t), api)
	require.NotNil(t, mngr)

	instances := ipamTypes.NewInstanceMap()
	for _, id := range []string{"intf-c", "intf-a", "intf-b"} {
		iface := &types.AzureInterface{SecurityGroup: "sg-" + id}
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

	var first *v2.CiliumNode
	for i := 0; i < 10; i++ {
		k8sObj := &v2.CiliumNode{}
		node.PopulateStatusFields(k8sObj)
		got := k8sObj.Status.Azure.Interfaces
		require.Len(t, got, 3, "iteration %d", i)
		require.True(t, got[0].ID < got[1].ID && got[1].ID < got[2].ID,
			"iteration %d: interfaces not sorted by ID: %v", i, got)
		if first == nil {
			first = k8sObj
			continue
		}
		require.True(t, first.Status.DeepEqual(&k8sObj.Status),
			"iteration %d: DeepEqual reported a spurious difference across randomized map order", i)
	}
}

type fakeNodeActions struct {
	instanceID string
}

func (f fakeNodeActions) InstanceID() string {
	return f.instanceID
}
