// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	envoypolicy "github.com/cilium/cilium/pkg/envoy/policy"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	proxyendpoint "github.com/cilium/cilium/pkg/proxy/endpoint"
	"github.com/cilium/cilium/pkg/revert"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
)

func policyOwnerIdFunc(id string) func() string {
	return func() string {
		return id
	}
}

type recordingEndpointProxy struct {
	mu lock.Mutex

	syncErrByEndpoint map[uint64]error
	completions       map[uint64]*completion.Completion
	revertCalls       map[uint64]int
	finalizeCalls     map[uint64]int

	updatesSeen     int
	expectedUpdates int
	updatesObserved chan struct{}
}

func newRecordingEndpointProxy() *recordingEndpointProxy {
	return &recordingEndpointProxy{
		syncErrByEndpoint: make(map[uint64]error),
		completions:       make(map[uint64]*completion.Completion),
		revertCalls:       make(map[uint64]int),
		finalizeCalls:     make(map[uint64]int),
	}
}

func (p *recordingEndpointProxy) expectUpdates(expected int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.completions = make(map[uint64]*completion.Completion)
	p.revertCalls = make(map[uint64]int)
	p.finalizeCalls = make(map[uint64]int)
	p.updatesSeen = 0
	p.expectedUpdates = expected
	p.updatesObserved = make(chan struct{})
}

func (p *recordingEndpointProxy) waitForUpdates(t *testing.T) {
	t.Helper()

	p.mu.Lock()
	ch := p.updatesObserved
	p.mu.Unlock()

	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for proxy update calls")
	}
}

func (p *recordingEndpointProxy) completeUpdate(t *testing.T, endpointID uint64, err error) {
	t.Helper()

	p.mu.Lock()
	comp := p.completions[endpointID]
	p.mu.Unlock()

	require.NotNilf(t, comp, "missing completion for endpoint %d", endpointID)
	comp.Complete(err)
}

func (p *recordingEndpointProxy) CreateOrUpdateRedirect(ctx context.Context, l4 policy.ProxyPolicy, id string, epID uint16, wg *completion.WaitGroup) (proxyPort uint16, err error, revertFunc revert.RevertFunc) {
	return 0, nil, nil
}

func (p *recordingEndpointProxy) RemoveRedirect(id string) {}

func (p *recordingEndpointProxy) UpdateNetworkPolicy(ep proxyendpoint.EndpointUpdater, epp *policy.EndpointPolicy, wg *completion.WaitGroup) (error, func() error) {
	endpointID := ep.GetID()

	p.mu.Lock()
	err := p.syncErrByEndpoint[endpointID]
	trackUpdates := p.expectedUpdates > 0
	if err == nil && wg != nil && trackUpdates {
		p.completions[endpointID] = wg.AddCompletionWithCallback(policyOwnerIdFunc("network-policy-update"), nil)
	}
	if trackUpdates {
		p.updatesSeen++
	}
	if trackUpdates && p.updatesSeen == p.expectedUpdates && p.updatesObserved != nil {
		close(p.updatesObserved)
	}
	p.mu.Unlock()

	if err != nil {
		return err, nil
	}

	return nil, func() error {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.revertCalls[endpointID]++
		return nil
	}
}

func (p *recordingEndpointProxy) RemoveNetworkPolicy(ep proxyendpoint.EndpointInfoSource) {
}

func (p *recordingEndpointProxy) UpdateSDP(rules map[identity.NumericIdentity]policy.SelectorPolicy) {
}

func (p *recordingEndpointProxy) GetListenerProxyPort(listener string) uint16 {
	return 0
}

func (p *recordingEndpointProxy) IsSDPEnabled() bool {
	return false
}

func (p *recordingEndpointProxy) updateCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.updatesSeen
}

func newUpdatePolicyMapsTestRepo(t *testing.T, withL7Rules bool) (*policy.Repository, identitymanager.IDManager) {
	t.Helper()

	logger := hivetest.Logger(t)
	idmgr := identitymanager.NewIDManager(logger)
	repo := policy.NewPolicyRepository(
		logger,
		nil,
		nil,
		envoypolicy.NewEnvoyL7RulesTranslator(logger, certificatemanager.NewMockSecretManagerInline()),
		idmgr,
		testpolicy.NewPolicyMetricsNoop(),
	)

	oldPolicyMode := policy.GetPolicyEnabled()
	policy.SetPolicyEnabled(option.DefaultEnforcement)
	t.Cleanup(func() {
		policy.SetPolicyEnabled(oldPolicyMode)
	})

	portRule := api.PortRule{
		Ports: []api.PortProtocol{{
			Port:     "80",
			Protocol: api.ProtoTCP,
		}},
	}
	if withL7Rules {
		portRule.Rules = &api.L7Rules{
			HTTP: []api.PortRuleHTTP{{
				Path:   "/",
				Method: "GET",
			}},
		}
	}
	repo.MustAddList(api.Rules{{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Ingress: []api.IngressRule{{
			ToPorts: []api.PortRule{portRule},
		}},
	}})

	return repo, idmgr
}

func newUpdatePolicyMapsTestEndpoint(t *testing.T, mgr *endpointManager, repo policy.PolicyRepository, idmgr identitymanager.IDManager, proxy endpoint.EndpointProxy, modelID int, addr netip.Addr) *endpoint.Endpoint {
	t.Helper()

	model := newTestEndpointModel(modelID, endpoint.StateWaitingForIdentity)
	ep, err := endpoint.NewEndpointFromChangeModel(
		t.Context(),
		hivetest.Logger(t),
		nil,
		&endpoint.MockEndpointBuildQueue{},
		nil,
		nil,
		nil,
		nil,
		nil,
		idmgr,
		nil,
		nil,
		repo,
		testipcache.NewMockIPCache(),
		proxy,
		testidentity.NewMockIdentityAllocator(nil),
		ctmap.NewFakeGCRunner(),
		ipcache.NewIPIdentitySynchronizer(
			hivetest.Logger(t),
			kvstore.SetupDummy(t, kvstore.DisabledBackendName),
		),
		model,
		fakeTypes.WireguardConfig{},
		fakeTypes.IPsecConfig{},
		nil,
		nil,
	)
	require.NoError(t, err)

	ep.Start(uint16(model.ID))
	t.Cleanup(ep.Stop)

	ep.IPv4 = addr
	ep.SetIdentity(identity.NewIdentityFromLabelArray(identity.NumericIdentity(1000+modelID), labels.ParseLabelArray("k8s:bar")))

	err = mgr.expose(ep)
	require.NoError(t, err)

	success := <-ep.RegenerateIfAlive(&regeneration.ExternalRegenerationMetadata{
		Reason:            "policy-update",
		RegenerationLevel: regeneration.RegenerateWithoutDatapath,
	})
	require.True(t, success)

	return ep
}

// TestIncrementalProxyPolicyUpdateNoL7Rule verifies that when an endpoint has no L7 rules,
// incremental policy updates are sent to Envoy only when EnvoyConfig is enabled.
func TestIncrementalProxyPolicyUpdateNoL7Rule(t *testing.T) {
	logger := hivetest.Logger(t)
	repo, idmgr := newUpdatePolicyMapsTestRepo(t, false)

	setEnvoyConfigOption := func(t *testing.T, value bool) {
		oldValue := option.Config.EnableEnvoyConfig
		option.Config.EnableEnvoyConfig = value
		t.Cleanup(func() { option.Config.EnableEnvoyConfig = oldValue })
	}

	t.Run("EnvoyConfigDisabled", func(t *testing.T) {
		setEnvoyConfigOption(t, false)
		mgr := New(logger, nil, &dummyEpSyncher{}, nil, nil, nil, defaultEndpointManagerConfig)
		proxy := newRecordingEndpointProxy()

		_ = newUpdatePolicyMapsTestEndpoint(t, mgr, repo, idmgr, proxy, 401, netip.MustParseAddr("10.0.3.1"))

		// Enable tracking so we can detect if the proxy is unexpectedly called.
		proxy.expectUpdates(1)
		require.NoError(t, mgr.UpdatePolicyMaps(t.Context()))

		// With EnvoyConfig disabled and no L7 rules, no update should be sent to the proxy.
		require.Equal(t, 0, proxy.updateCount())
	})

	t.Run("EnvoyConfigEnabled", func(t *testing.T) {
		setEnvoyConfigOption(t, true)
		mgr := New(logger, nil, &dummyEpSyncher{}, nil, nil, nil, defaultEndpointManagerConfig)
		proxy := newRecordingEndpointProxy()

		ep := newUpdatePolicyMapsTestEndpoint(t, mgr, repo, idmgr, proxy, 402, netip.MustParseAddr("10.0.3.2"))
		proxy.expectUpdates(1)

		errCh := make(chan error, 1)
		go func() {
			errCh <- mgr.UpdatePolicyMaps(t.Context())
		}()

		// With EnvoyConfig enabled, the proxy must receive the incremental update even
		// though there are no L7 rules.
		proxy.waitForUpdates(t)
		proxy.completeUpdate(t, ep.GetID(), nil)

		require.NoError(t, <-errCh)
		require.Equal(t, 1, proxy.updateCount())
	})
}
