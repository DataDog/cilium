// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

// TestHostIPWorldFallbackDuringRestartWindow and related tests reproduce a bug
// where node/host IPs that fall within a CiliumCIDRGroup CIDR are transiently
// misclassified as "world" identity during rolling Cilium agent restarts.
//
// Root cause (two code paths, both required):
//
// 1. pkg/ipcache/restore/local_identity_restorer.go:128
//    dumpOldIPCache() only restores IdentityScopeLocal and ReservedIdentityIngress
//    identities. ReservedIdentityHost (scope=global, id=1) is explicitly excluded.
//    After ipcachemap.Recreate(), the new BPF ipcache map has no entry for host IPs.
//
// 2. daemon/cmd/daemon.go startup ordering
//    K8sWatcher.InitK8sSubsystem() starts at line 202 (begins processing
//    CiliumCIDRGroups). syncHostIPs.StartAndWaitFirst() is not called until
//    line 249. During this window, a host IP covered by a CiliumCIDRGroup
//    receives only a cidrgroup label — no reserved:host.
//
// 3. pkg/ipcache/metadata.go:798 (resolveLabels)
//    Any IP without reserved:host, reserved:remote-node, reserved:health, or
//    reserved:ingress has AddWorldLabel() called on it. A host IP with only
//    a cidrgroup label is therefore assigned world identity.
//
// Impact: CNPs using "fromEntities: cluster" do not cover world (id=2). Traffic
// from the misclassified host IP is denied with policy_denied.

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

// cidrGroupLabels returns a Labels set simulating what a CiliumCIDRGroup
// reconciler injects via UpsertMetadata for an IP that matches a
// CiliumCIDRGroup (e.g. a group covering a node-local subnet).
func cidrGroupLabels(groupName string) labels.Labels {
	return labels.Labels{
		groupName: labels.NewLabel(groupName, "", labels.LabelSourceCIDRGroup),
	}
}

// TestHostIPWorldFallbackDuringRestartWindow reproduces the bug where a host IP
// covered by a CiliumCIDRGroup is assigned world identity because resolveLabels()
// runs with only cidrgroup labels — before syncHostIPs has inserted reserved:host.
//
// This test asserts the CURRENT BUGGY BEHAVIOUR. It is expected to fail once
// the root cause is fixed (e.g. by ensuring host IPs are seeded into ipcache
// metadata before CiliumCIDRGroup processing can trigger resolveLabels for
// those prefixes, or by restoring host identity entries in dumpOldIPCache).
func TestHostIPWorldFallbackDuringRestartWindow(t *testing.T) {
	s := setupIPCacheTestSuite(t)
	ctx := t.Context()

	// Disable PolicyCIDRMatchMode to avoid interference from node-CIDR matching.
	oldVal := option.Config.PolicyCIDRMatchMode
	t.Cleanup(func() { option.Config.PolicyCIDRMatchMode = oldVal })
	option.Config.PolicyCIDRMatchMode = []string{}

	// A host IP that falls within a CiliumCIDRGroup subnet.
	hostIPPrefix := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("10.161.39.126/32"))

	// ── Stage 1: Restart window ──────────────────────────────────────────────
	// The K8s watcher has processed a CiliumCIDRGroup covering this IP's subnet.
	// The ipcache BPF map has been recreated empty (dumpOldIPCache skipped this
	// IP since ReservedIdentityHost is not locally-scoped). syncHostIPs has NOT
	// run yet — only the cidrgroup label is present.
	s.IPIdentityCache.metadata.upsertLocked(
		hostIPPrefix,
		source.Generated,
		"cidrgroup-resource-uid",
		cidrGroupLabels("example-local-subnet"),
	)

	_, err := s.IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{hostIPPrefix})
	require.NoError(t, err)

	entry, ok := s.IPIdentityCache.ipToIdentityCache["10.161.39.126/32"]
	require.True(t, ok, "expected an identity entry for the host IP")

	assignedID := entry.ID

	// Verify the assigned identity is NOT reserved:host (id=1).
	// This demonstrates the bug: the IP should be host but is not.
	assert.NotEqual(t, identity.ReservedIdentityHost, assignedID,
		"BUG REPRODUCED: host IP was not assigned ReservedIdentityHost (id=1). "+
			"Got id=%d. This occurs because resolveLabels() ran with only cidrgroup "+
			"labels (no reserved:host) during the restart window before syncHostIPs "+
			"executed.",
		assignedID)

	// Verify the assigned identity carries a world label — the world fallback fired.
	resolvedIdentity := s.Allocator.LookupIdentityByID(ctx, assignedID)
	require.NotNil(t, resolvedIdentity, "identity %d should be resolvable", assignedID)
	assert.True(t,
		resolvedIdentity.Labels.HasWorldLabel() || resolvedIdentity.Labels.HasWorldIPv4Label(),
		"BUG: host IP was assigned world identity (id=%d, labels=%v). "+
			"resolveLabels() called AddWorldLabel() because HasHostLabel()=false. "+
			"Traffic from this IP will be denied by CNPs that use 'fromEntities: cluster' "+
			"because world (id=2) is not in the cluster entity.",
		assignedID, resolvedIdentity.Labels)

	// ── Stage 2: syncHostIPs runs ────────────────────────────────────────────
	// After daemon initialisation completes (daemon.go:249), syncHostIPs inserts
	// the reserved:host label. resolveLabels() now sees HasHostLabel()=true,
	// sets isInCluster=true, removes cidrgroup labels, and does NOT add world.
	s.IPIdentityCache.metadata.upsertLocked(
		hostIPPrefix,
		source.Local,
		"daemon-reserved",
		labels.LabelHost,
	)

	_, err = s.IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{hostIPPrefix})
	require.NoError(t, err)

	correctedEntry, ok := s.IPIdentityCache.ipToIdentityCache["10.161.39.126/32"]
	require.True(t, ok)

	// After syncHostIPs runs, the identity must be corrected to reserved:host.
	assert.Equal(t, identity.ReservedIdentityHost, correctedEntry.ID,
		"After syncHostIPs inserts reserved:host, identity should be corrected to "+
			"ReservedIdentityHost (id=1). Got id=%d.", correctedEntry.ID)
}

// TestWorldFallbackDoesNotOccurWhenHostLabelPresentFirst verifies the CORRECT
// behaviour: when reserved:host is already present before CIDRGroup labels arrive,
// resolveLabels() correctly identifies the IP as in-cluster and does not add
// the world label.
//
// This is the inverse of TestHostIPWorldFallbackDuringRestartWindow and
// documents the expected steady-state behaviour (no restart window).
func TestWorldFallbackDoesNotOccurWhenHostLabelPresentFirst(t *testing.T) {
	s := setupIPCacheTestSuite(t)
	ctx := t.Context()

	oldVal := option.Config.PolicyCIDRMatchMode
	t.Cleanup(func() { option.Config.PolicyCIDRMatchMode = oldVal })
	option.Config.PolicyCIDRMatchMode = []string{}

	hostIPPrefix := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("10.161.39.126/32"))

	// syncHostIPs runs FIRST (correct startup order / no restart window).
	s.IPIdentityCache.metadata.upsertLocked(
		hostIPPrefix,
		source.Local,
		"daemon-reserved",
		labels.LabelHost,
	)

	// CiliumCIDRGroup label arrives afterwards (normal steady-state order).
	s.IPIdentityCache.metadata.upsertLocked(
		hostIPPrefix,
		source.Generated,
		"cidrgroup-resource-uid",
		cidrGroupLabels("example-local-subnet"),
	)

	_, err := s.IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{hostIPPrefix})
	require.NoError(t, err)

	entry, ok := s.IPIdentityCache.ipToIdentityCache["10.161.39.126/32"]
	require.True(t, ok)

	// When reserved:host is present first, identity must be ReservedIdentityHost.
	assert.Equal(t, identity.ReservedIdentityHost, entry.ID,
		"When reserved:host is in ipcache metadata before CIDRGroup labels arrive, "+
			"the identity must be ReservedIdentityHost (id=1). Got id=%d.", entry.ID)

	resolvedIdentity := s.Allocator.LookupIdentityByID(ctx, entry.ID)
	require.NotNil(t, resolvedIdentity)
	assert.False(t,
		resolvedIdentity.Labels.HasWorldLabel() || resolvedIdentity.Labels.HasWorldIPv4Label(),
		"Identity must not have world label when reserved:host is present. Labels: %v",
		resolvedIdentity.Labels)
}
