// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package doublewrite

import (
	"context"
	"fmt"
	"path"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/identity/key"
	"github.com/cilium/cilium/pkg/idpool"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/identitybackend"
	kvstoreallocator "github.com/cilium/cilium/pkg/kvstore/allocator"
	"github.com/cilium/cilium/pkg/labels"

	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/testutils"
)

func setup(tb testing.TB) (string, *k8sClient.FakeClientset, *allocator.Backend) {
	tb.Helper()

	testutils.IntegrationTest(tb)

	kvstore.SetupDummy(tb, "etcd")
	kvstorePrefix := fmt.Sprintf("test-prefix-%s", rand.String(12))
	kubeClient, _ := k8sClient.NewFakeClientset()
	backend, err := NewDoubleWriteBackend(
		DoubleWriteBackendConfiguration{
			CRDBackendConfiguration: identitybackend.CRDBackendConfiguration{
				Store:   nil,
				Client:  kubeClient,
				KeyFunc: (&key.GlobalIdentity{}).PutKeyFromMap,
			},
			KVStoreBackendConfiguration: kvstoreallocator.KVStoreBackendConfiguration{
				BasePath: kvstorePrefix,
				Suffix:   "a",
				Typ:      &key.GlobalIdentity{},
				Backend:  kvstore.Client(),
			},
			ReadFromKVStore: true,
		})
	require.Nil(tb, err)
	require.NotNil(tb, backend)

	return kvstorePrefix, kubeClient, &backend
}

func TestAllocateID(t *testing.T) {
	kvstorePrefix, kubeClient, backend := setup(t)

	// Allocate a new identity
	lbls := labels.NewLabelsFromSortedList("id=foo")
	k := &key.GlobalIdentity{LabelArray: lbls.LabelArray()}
	identityID := idpool.ID(10)
	_, err := (*backend).AllocateID(context.Background(), identityID, k)
	require.Nil(t, err)

	// Verify that both the CRD and the KVStore identities have been created
	// 1. CRD
	ids, err := kubeClient.CiliumV2().CiliumIdentities().List(context.Background(), metav1.ListOptions{})
	require.Nil(t, err)
	require.Len(t, ids.Items, 1)
	require.Equal(t, ids.Items[0].Name, identityID.String())
	require.EqualValues(t,
		ids.Items[0].SecurityLabels,
		map[string]string{fmt.Sprintf("%s:%s", lbls.LabelArray()[0].Source, lbls.LabelArray()[0].Key): lbls.LabelArray()[0].Value},
	)

	// 2. KVStore
	kvPairs, err := kvstore.Client().ListPrefix(context.Background(), path.Join(kvstorePrefix, "id"))
	require.Nil(t, err)
	require.Len(t, kvPairs, 1)
	require.Equal(t,
		string(kvPairs[fmt.Sprintf("%s/id/%s", kvstorePrefix, identityID)].Data),
		fmt.Sprintf("%s:%s=%s;", lbls.LabelArray()[0].Source, lbls.LabelArray()[0].Key, lbls.LabelArray()[0].Value),
	)
}

func TestGetID(t *testing.T) {
	kvstorePrefix, kubeClient, backend := setup(t)

	// Allocate a new identity
	lbls := labels.NewLabelsFromSortedList("id=foo")
	k := &key.GlobalIdentity{LabelArray: lbls.LabelArray()}
	identityID := idpool.ID(10)
	_, err := (*backend).AllocateID(context.Background(), identityID, k)
	require.Nil(t, err)

	// Get the identity. It will be retrieved from the KVStore ("ReadFromKVStore: true").
	returnedKey, err := (*backend).GetByID(context.Background(), identityID)
	require.Nil(t, err)
	require.Equal(t, returnedKey.GetKey(), k.GetKey())

	// Delete the CRD identity
	err = kubeClient.CiliumV2().CiliumIdentities().Delete(context.Background(), identityID.String(), metav1.DeleteOptions{})
	require.Nil(t, err)

	// Verify that the identity is still retrievable from the KVStore
	returnedKey, err = (*backend).GetByID(context.Background(), identityID)
	require.Nil(t, err)
	require.Equal(t, returnedKey.GetKey(), k.GetKey())

	// Delete the KVStore identity
	err = kvstore.Client().Delete(context.Background(), path.Join(kvstorePrefix, "id", identityID.String()))
	require.Nil(t, err)

	// Verify that we can't retrieve the identity anymore
	returnedKey, err = (*backend).GetByID(context.Background(), identityID)
	require.Nil(t, err)
	require.Nil(t, returnedKey)
}