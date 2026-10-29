// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodediscovery

import (
	"context"
	"fmt"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stesting "k8s.io/client-go/testing"

	apimodels "github.com/cilium/cilium/api/v1/models"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	clienttestutils "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	cnitypes "github.com/cilium/cilium/plugins/cilium-cni/types"
)

// mockK8sGetters implements k8sGetters returning a pre-existing CiliumNode,
// so updateCiliumNodeResource takes the Update path (not Create).
type mockK8sGetters struct {
	ciliumNode *ciliumv2.CiliumNode
}

func (m *mockK8sGetters) GetCiliumNode(_ context.Context, _ string) (*ciliumv2.CiliumNode, error) {
	return m.ciliumNode.DeepCopy(), nil
}

// mockCNIConfigManager implements cni.CNIConfigManager with no-op methods.
type mockCNIConfigManager struct{}

func (m *mockCNIConfigManager) GetMTU() int                         { return 0 }
func (m *mockCNIConfigManager) GetChainingMode() string             { return "" }
func (m *mockCNIConfigManager) Status() *apimodels.Status           { return nil }
func (m *mockCNIConfigManager) GetCustomNetConf() *cnitypes.NetConf { return nil }
func (m *mockCNIConfigManager) ExternalRoutingEnabled() bool        { return false }

// TestUpdateCiliumNodeResourceTransientErrorCausesFatal reproduces
// https://github.com/cilium/cilium/issues/44388: a transient error from the
// API server during a CiliumNode Update caused logging.Fatal instead of being
// retried.
func TestUpdateCiliumNodeResourceTransientErrorCausesFatal(t *testing.T) {
	logging.RegisterExitHandler(func() { panic("fatal called") })
	t.Cleanup(func() { logging.RegisterExitHandler(func() {}) })

	option.Config.AutoCreateCiliumNodeResource = true
	option.Config.IPAM = ""
	t.Cleanup(func() {
		option.Config.AutoCreateCiliumNodeResource = false
	})

	const nodeName = "test-node"
	nodeTypes.SetName(nodeName)

	fakeClient, _ := clienttestutils.NewFakeClientset(hivetest.Logger(t))

	existingNode := &ciliumv2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{Name: nodeName},
	}
	require.NoError(t, fakeClient.CiliumFakeClientset.Tracker().Add(existingNode))

	updateCalls := 0
	// PrependReactor is required: the tracker's ObjectReaction (added at
	// clientset creation via AddReactor) would otherwise intercept Update
	// first and return a Conflict error due to the missing resource version.
	fakeClient.CiliumFakeClientset.PrependReactor("update", "ciliumnodes",
		func(_ k8stesting.Action) (bool, runtime.Object, error) {
			updateCalls++
			return true, nil, fmt.Errorf("connection reset by peer")
		},
	)

	nd := &NodeDiscovery{
		logger:           hivetest.Logger(t),
		clientset:        fakeClient,
		k8sGetters:       &mockK8sGetters{ciliumNode: existingNode},
		cniConfigManager: &mockCNIConfigManager{},
	}

	ln := &node.LocalNode{
		Node:  nodeTypes.Node{Name: nodeName},
		Local: &node.LocalNodeInfo{},
	}

	require.Panics(t, func() {
		nd.updateCiliumNodeResource(context.Background(), ln)
	})

	require.Equal(t, maxRetryCount, updateCalls,
		"transient errors should be retried %d times, not fataled immediately", maxRetryCount)
}

func setupConflictTest(t *testing.T) (*NodeDiscovery, *clienttestutils.FakeClientset, *node.LocalNode) {
	logging.RegisterExitHandler(func() { panic("fatal called") })
	t.Cleanup(func() { logging.RegisterExitHandler(func() {}) })

	option.Config.AutoCreateCiliumNodeResource = true
	option.Config.IPAM = ""
	t.Cleanup(func() {
		option.Config.AutoCreateCiliumNodeResource = false
	})

	const nodeName = "test-node"
	nodeTypes.SetName(nodeName)

	fakeClient, _ := clienttestutils.NewFakeClientset(hivetest.Logger(t))

	// The informer store lags behind: it only knows about resourceVersion 1.
	staleNode := &ciliumv2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{Name: nodeName, ResourceVersion: "1"},
	}

	nd := &NodeDiscovery{
		logger:           hivetest.Logger(t),
		clientset:        fakeClient,
		k8sGetters:       &mockK8sGetters{ciliumNode: staleNode},
		cniConfigManager: &mockCNIConfigManager{},
	}
	ln := &node.LocalNode{
		Node:  nodeTypes.Node{Name: nodeName},
		Local: &node.LocalNodeInfo{},
	}
	return nd, fakeClient, ln
}

var ciliumNodeGR = schema.GroupResource{Group: "cilium.io", Resource: "ciliumnodes"}

// TestUpdateCiliumNodeResourceStaleCacheConflict verifies that a Conflict
// caused by a stale informer store is resolved by re-reading the CiliumNode
// from the kube-apiserver, rather than retrying with the same stale
// resourceVersion until the retry budget is exhausted.
func TestUpdateCiliumNodeResourceStaleCacheConflict(t *testing.T) {
	nd, fakeClient, ln := setupConflictTest(t)

	const currentRV = "5"
	var updateCalls, getCalls int
	fakeClient.CiliumFakeClientset.PrependReactor("get", "ciliumnodes",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			getCalls++
			return true, &ciliumv2.CiliumNode{
				ObjectMeta: metav1.ObjectMeta{Name: action.(k8stesting.GetAction).GetName(), ResourceVersion: currentRV},
			}, nil
		},
	)
	fakeClient.CiliumFakeClientset.PrependReactor("update", "ciliumnodes",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			updateCalls++
			obj := action.(k8stesting.UpdateAction).GetObject().(*ciliumv2.CiliumNode)
			if obj.ResourceVersion != currentRV {
				return true, nil, k8serrors.NewConflict(ciliumNodeGR, obj.Name,
					fmt.Errorf("the object has been modified; please apply your changes to the latest version and try again"))
			}
			return true, obj, nil
		},
	)

	require.NotPanics(t, func() {
		nd.updateCiliumNodeResource(context.Background(), ln)
	})
	require.Equal(t, 2, updateCalls, "expected one conflicting update followed by a successful one")
	require.Equal(t, 1, getCalls, "expected a direct GET from the kube-apiserver after the conflict")
}

// TestUpdateCiliumNodeResourceConflictsDoNotConsumeRetryBudget verifies that
// sustained conflicts (e.g. with the operator concurrently updating the
// CiliumNode) do not exhaust the retry budget reserved for other errors.
func TestUpdateCiliumNodeResourceConflictsDoNotConsumeRetryBudget(t *testing.T) {
	nd, fakeClient, ln := setupConflictTest(t)

	const conflictsBeforeSuccess = maxRetryCount + 2
	var updateCalls int
	fakeClient.CiliumFakeClientset.PrependReactor("get", "ciliumnodes",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, &ciliumv2.CiliumNode{
				ObjectMeta: metav1.ObjectMeta{Name: action.(k8stesting.GetAction).GetName()},
			}, nil
		},
	)
	fakeClient.CiliumFakeClientset.PrependReactor("update", "ciliumnodes",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			updateCalls++
			obj := action.(k8stesting.UpdateAction).GetObject()
			if updateCalls <= conflictsBeforeSuccess {
				return true, nil, k8serrors.NewConflict(ciliumNodeGR, "test-node", fmt.Errorf("the object has been modified"))
			}
			return true, obj, nil
		},
	)

	require.NotPanics(t, func() {
		nd.updateCiliumNodeResource(context.Background(), ln)
	})
	require.Equal(t, conflictsBeforeSuccess+1, updateCalls)
}

// TestUpdateCiliumNodeResourceCreateAlreadyExists verifies that if the
// informer store does not yet know about the CiliumNode, but it already
// exists in the kube-apiserver, the resulting AlreadyExists error on Create
// is followed by a direct GET and an Update.
func TestUpdateCiliumNodeResourceCreateAlreadyExists(t *testing.T) {
	nd, fakeClient, ln := setupConflictTest(t)
	nd.k8sGetters = &notFoundK8sGetters{}

	var createCalls, updateCalls int
	fakeClient.CiliumFakeClientset.PrependReactor("get", "ciliumnodes",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, &ciliumv2.CiliumNode{
				ObjectMeta: metav1.ObjectMeta{Name: action.(k8stesting.GetAction).GetName()},
			}, nil
		},
	)
	fakeClient.CiliumFakeClientset.PrependReactor("create", "ciliumnodes",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			createCalls++
			return true, nil, k8serrors.NewAlreadyExists(ciliumNodeGR, "test-node")
		},
	)
	fakeClient.CiliumFakeClientset.PrependReactor("update", "ciliumnodes",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			updateCalls++
			return true, action.(k8stesting.UpdateAction).GetObject(), nil
		},
	)

	require.NotPanics(t, func() {
		nd.updateCiliumNodeResource(context.Background(), ln)
	})
	require.Equal(t, 1, createCalls)
	require.Equal(t, 1, updateCalls)
}

type notFoundK8sGetters struct{}

func (notFoundK8sGetters) GetCiliumNode(_ context.Context, name string) (*ciliumv2.CiliumNode, error) {
	return nil, k8serrors.NewNotFound(ciliumNodeGR, name)
}
