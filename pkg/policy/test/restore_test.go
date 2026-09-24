// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/clustermesh"
	"github.com/cilium/cilium/pkg/clustermesh/wait"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointtypes "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity"
	ipcachetypes "github.com/cilium/cilium/pkg/ipcache/types"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	testk8s "github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/policy/api"
	policyutils "github.com/cilium/cilium/pkg/policy/utils"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
)

func TestRestoredEndpointRealizesLabelSelectedPolicy(t *testing.T) {
	t.Cleanup(func() {
		testutils.GoleakVerifyNone(t,
			testutils.GoleakIgnoreAnyFunction("github.com/cilium/cilium/pkg/trigger.(*Trigger).waiter"),
			testutils.GoleakIgnoreAnyFunction("github.com/cilium/cilium/pkg/policy.(*SelectorCache).handleUserNotifications"),
		)
	})

	version.Force(testk8s.DefaultVersion)

	for _, tc := range []struct {
		name                string
		updateDuringRestore bool
	}{
		{name: "no policy update during identity restore", updateDuringRestore: false},
		{name: "policy update during identity restore", updateDuringRestore: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testRestoredEndpointRealizesLabelSelectedPolicy(t, tc.updateDuringRestore)
		})
	}
}

func testRestoredEndpointRealizesLabelSelectedPolicy(t *testing.T, updateDuringRestore bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	log := hivetest.Logger(t)
	require.NoError(t, labelsfilter.ParseLabelPrefixCfg(log, nil, nil, ""))

	t.Chdir(t.TempDir())

	f := newTestFixture(t, log, nil)
	regenerator := newTestRegenerator(t, log)

	podLabels := labels.LabelArray{
		labels.NewLabel(k8sConst.PodNamespaceLabel, "default", labels.LabelSourceK8s),
		labels.NewLabel("app", "restored", labels.LabelSourceK8s),
	}
	restoredID, _, err := f.allocator.AllocateIdentity(ctx, podLabels.Labels(), true, identity.InvalidIdentity)
	require.NoError(t, err)

	labelSelectedPolicy := labels.NewLabel(k8sConst.PolicyLabelName, "restored-app", labels.LabelSourceK8s)
	applyPolicyUpdate(t, f, ipcachetypes.NewResourceID(ipcachetypes.ResourceKindCNP, "default", "restored-app"), &api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.NewLabel("app", "restored", labels.LabelSourceK8s)),
		Egress: []api.EgressRule{{
			EgressCommonRule: api.EgressCommonRule{
				ToEndpoints: []api.EndpointSelector{api.NewESFromLabels(labels.NewLabel("app", "peer", labels.LabelSourceK8s))},
			},
			ToPorts: []api.PortRule{{Ports: []api.PortProtocol{{Port: "80", Protocol: api.ProtoTCP}}}},
		}},
		Labels: labels.LabelArray{labelSelectedPolicy},
	})

	wildcardPolicy := labels.NewLabel(k8sConst.PolicyLabelName, "cluster-wildcard", labels.LabelSourceK8s)
	applyPolicyUpdate(t, f, ipcachetypes.NewResourceID(ipcachetypes.ResourceKindCCNP, "", "cluster-wildcard"), &api.Rule{
		EndpointSelector: api.WildcardEndpointSelector,
		Egress: []api.EgressRule{{
			ToPorts: []api.PortRule{{Ports: []api.PortProtocol{{Port: "53", Protocol: api.ProtoUDP}}}},
		}},
		Labels: labels.LabelArray{wildcardPolicy},
	})

	ep := parseRestoredEndpoint(t, f, 1234, podLabels, restoredID)
	require.Nil(t, f.idmgr.Get(&restoredID.ID), "restored identity must not be registered before restoreIdentity runs")
	require.NoError(t, f.epm.RestoreEndpoint(ep))

	rev := f.repo.GetRevision()
	if updateDuringRestore {
		rev = applyPolicyUpdate(t, f, ipcachetypes.NewResourceID(ipcachetypes.ResourceKindCNP, "other", "unrelated"), &api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.NewLabel("app", "unrelated", labels.LabelSourceK8s)),
			Egress: []api.EgressRule{{
				ToPorts: []api.PortRule{{Ports: []api.PortProtocol{{Port: "443", Protocol: api.ProtoTCP}}}},
			}},
			Labels: labels.LabelArray{labels.NewLabel(k8sConst.PolicyLabelName, "unrelated", labels.LabelSourceK8s)},
		})
	}
	drainPolicyComputations(t, ctx, f)

	require.NoError(t, ep.RegenerateAfterRestore(regenerator, func(string, string, string, bool) (*slim_corev1.Pod, *endpoint.K8sMetadata, error) {
		return nil, nil, errors.New("metadata lookup not expected for an endpoint without a pod")
	}))

	realized, realizedRev, err := ep.GetRealizedL4PolicyRuleOriginModel()
	require.NoError(t, err)
	require.GreaterOrEqual(t, realizedRev, rev)

	origins := egressRuleOrigins(realized.Egress)
	require.Contains(t, origins, wildcardPolicy.String())
	require.Contains(t, origins, labelSelectedPolicy.String(),
		"restored endpoint realized a policy computed before its identity was registered for subject matching")
}

func applyPolicyUpdate(t *testing.T, f *testFixture, resource ipcachetypes.ResourceID, rule *api.Rule) uint64 {
	t.Helper()
	require.NoError(t, rule.Sanitize())

	fromRev := f.repo.GetRevision()
	affected, toRev, _ := f.repo.ReplaceByResource(policyutils.RulesToPolicyEntries(api.Rules{rule}), resource)
	f.computer.UpdatePolicy(*affected, fromRev, toRev)
	f.epm.UpdatePolicy(affected, fromRev, toRev)
	return toRev
}

func drainPolicyComputations(t *testing.T, ctx context.Context, f *testFixture) {
	t.Helper()

	barrierLabels := labels.LabelArray{
		labels.NewLabel(k8sConst.PodNamespaceLabel, "default", labels.LabelSourceK8s),
		labels.NewLabel("app", "barrier", labels.LabelSourceK8s),
	}
	barrierID, _, err := f.allocator.AllocateIdentity(ctx, barrierLabels.Labels(), true, identity.InvalidIdentity)
	require.NoError(t, err)
	f.idmgr.Add(barrierID)
	t.Cleanup(func() { f.idmgr.Remove(barrierID) })

	done, err := f.computer.RecomputeIdentityPolicy(barrierID, f.repo.GetRevision()+1)
	require.NoError(t, err)
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("policy computation queue did not drain")
	}
}

func parseRestoredEndpoint(t *testing.T, f *testFixture, id uint16, lbls labels.LabelArray, secID *identity.Identity) *endpoint.Endpoint {
	t.Helper()

	raw, err := json.Marshal(f.templateEP.CopyFromTemplate())
	require.NoError(t, err)
	var serialized map[string]any
	require.NoError(t, json.Unmarshal(raw, &serialized))

	opLabels := labels.NewOpLabels()
	opLabels.OrchestrationIdentity = lbls.Labels()
	serialized["ID"] = id
	serialized["OpLabels"] = opLabels
	serialized["SecLabel"] = secID
	raw, err = json.Marshal(serialized)
	require.NoError(t, err)

	ep, err := endpoint.ParseEndpoint(f.epParams, &fakeDNSAPI{}, &endpoint.FakeEndpointProxy{}, raw, t.Output())
	require.NoError(t, err)
	ep.SetPropertyValue(endpointtypes.PropertyFakeEndpoint, true)
	return ep
}

func newTestRegenerator(t *testing.T, log *slog.Logger) *endpoint.Regenerator {
	t.Helper()

	var regenerator *endpoint.Regenerator
	h := hive.New(
		endpoint.RegeneratorCell,
		cell.Provide(
			func() wait.TimeoutConfig { return wait.TimeoutConfig{ClusterMeshSyncTimeout: time.Second} },
			func() *clustermesh.ClusterMesh { return nil },
			func() loadbalancer.InitWaitFunc { return func(context.Context) error { return nil } },
		),
		cell.Invoke(func(r *endpoint.Regenerator) { regenerator = r }),
	)
	require.NoError(t, h.Start(log, context.Background()))
	t.Cleanup(func() { assert.NoError(t, h.Stop(log, context.Background())) })
	return regenerator
}

func egressRuleOrigins(rules []*models.PolicyRule) []string {
	var origins []string
	for _, rule := range rules {
		for _, derivedFrom := range rule.DerivedFromRules {
			origins = append(origins, derivedFrom...)
		}
	}
	return origins
}
