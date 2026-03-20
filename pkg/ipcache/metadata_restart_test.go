// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

// TestHostIPWorldFallbackDuringRestartWindow and TestHostIdentityRestorationGap
// reproduce a bug observed in production (us1.fed.dog, 2026-03-20) where node/host
// IPs in a local-DC CIDR were misclassified as "world" identity during rolling
// Cilium agent restarts, causing policy_denied drops against cluster-dns.
//
// Root cause (two code paths, both required):
//
// 1. pkg/ipcache/restore/local_identity_restorer.go:128
//    dumpOldIPCache() filters restored identities to IdentityScopeLocal and
//    ReservedIdentityIngress only. ReservedIdentityHost (scope=global, id=1) is
//    explicitly excluded. After ipcachemap.Recreate(), the new BPF map has no
//    entry for host IPs.
//
// 2. daemon/cmd/daemon.go startup ordering
//    K8sWatcher.InitK8sSubsystem() starts at line 202 (begins processing
//    CiliumCIDRGroups managed by fabric-k8s-controller). syncHostIPs.StartAndWaitFirst()
//    is not called until line 249. During this window, a host IP in the local-DC
//    CiliumCIDRGroup (e.g. 10.160.0.0/14) receives only a cidrgroup label.
//
// 3. pkg/ipcache/metadata.go:798 (resolveLabels)
//    Any IP without reserved:host, reserved:remote-node, reserved:health, or
//    reserved:ingress label has AddWorldLabel() called on it. A host IP with only
//    a cidrgroup label therefore becomes world — which is not covered by the
//    cluster-dns CNP's "fromEntities: cluster" ingress rule, causing drops.

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

// cidrGroupLabels returns a Labels set simulating what the CiliumCIDRGroup reconciler
// (fabric-k8s-controller) injects via UpsertMetadata for an IP that matches a
// CiliumCIDRGroup (e.g. the "local-dc" group covering 10.160.0.0/14).
func cidrGroupLabels(groupName string) labels.Labels {
	return labels.Labels{
		groupName: labels.NewLabel(groupName, "", labels.LabelSourceCIDRGroup),
	}
}

// TestHostIPWorldFallbackDuringRestartWindow reproduces the bug where a host IP
// is assigned world identity because resolveLabels() runs with only cidrgroup labels
// — before syncHostIPs has inserted the reserved:host label.
//
// This test asserts the CURRENT BUGGY BEHAVIOR. It is expected to fail once the
// bug is fixed (e.g. by ensuring host IPs are seeded into ipcache metadata before
// CiliumCIDRGroup processing can trigger resolveLabels for those prefixes).
func TestHostIPWorldFallbackDuringRestartWindow(t *testing.T) {
	s := setupIPCacheTestSuite(t)
	ctx := t.Context()

	// Disable PolicyCIDRMatchMode to avoid interference from node-CIDR matching.
	oldVal := option.Config.PolicyCIDRMatchMode
	t.Cleanup(func() { option.Config.PolicyCIDRMatchMode = oldVal })
	option.Config.PolicyCIDRMatchMode = []string{}

	// The host IP observed in production: 10.161.39.126 (in 10.160.0.0/14, localDc CIDR).
	// 8,258 drops were recorded against cluster-dns over 48h.
	hostIPPrefix := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("10.161.39.126/32"))

	// ── Stage 1: Restart window ──────────────────────────────────────────────
	// K8sWatcher has processed the "local-dc" CiliumCIDRGroup. The ipcache BPF
	// map has been recreated empty (RestoreLocalIdentities skipped this IP since
	// ReservedIdentityHost is not locally-scoped). syncHostIPs has NOT run yet.
	//
	// Only the cidrgroup label is present — no reserved:host.
	s.IPIdentityCache.metadata.upsertLocked(
		hostIPPrefix,
		source.Generated,
		"cidrgroup-resource-uid",
		cidrGroupLabels("local-dc"),
	)

	_, err := s.IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{hostIPPrefix})
	require.NoError(t, err)

	entry, ok := s.IPIdentityCache.ipToIdentityCache["10.161.39.126/32"]
	require.True(t, ok, "expected an identity entry for 10.161.39.126/32")

	assignedID := entry.ID

	// Verify the assigned identity is NOT reserved:host (id=1).
	// This demonstrates the bug: the IP should be host but is not.
	assert.NotEqual(t, identity.ReservedIdentityHost, assignedID,
		"BUG REPRODUCED: host IP 10.161.39.126 was not assigned ReservedIdentityHost (id=1). "+
			"Got id=%d. This occurs because resolveLabels() ran with only cidrgroup labels "+
			"(no reserved:host) during the restart window before syncHostIPs executed.",
		assignedID)

	// Verify the assigned identity has a world label — the world fallback fired.
	resolvedIdentity := s.Allocator.LookupIdentityByID(ctx, assignedID)
	require.NotNil(t, resolvedIdentity, "identity %d should be resolvable", assignedID)
	assert.True(t,
		resolvedIdentity.Labels.HasWorldLabel() || resolvedIdentity.Labels.HasWorldIPv4Label(),
		"BUG: host IP 10.161.39.126/32 was assigned world identity (id=%d, labels=%v). "+
			"resolveLabels() called AddWorldLabel() because HasHostLabel()=false. "+
			"This causes policy_denied drops: the cluster-dns CNP allows 'fromEntities: cluster' "+
			"but world (id=2) is not in the cluster entity.",
		assignedID, resolvedIdentity.Labels)

	// ── Stage 2: syncHostIPs runs ────────────────────────────────────────────
	// After daemon initialization completes (daemon.go:249), syncHostIPs inserts
	// the reserved:host label for this IP. resolveLabels() now sees HasHostLabel()=true,
	// sets isInCluster=true, removes the cidrgroup label, and does NOT add world.
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
// behaviour: when reserved:host is present before CIDRGroup labels are processed,
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
		cidrGroupLabels("local-dc"),
	)

	_, err := s.IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{hostIPPrefix})
	require.NoError(t, err)

	entry, ok := s.IPIdentityCache.ipToIdentityCache["10.161.39.126/32"]
	require.True(t, ok)

	// When reserved:host is present, the identity must be ReservedIdentityHost.
	assert.Equal(t, identity.ReservedIdentityHost, entry.ID,
		"When reserved:host is already in ipcache metadata before CIDRGroup labels "+
			"arrive, the identity must be ReservedIdentityHost (id=1). Got id=%d.", entry.ID)

	resolvedIdentity := s.Allocator.LookupIdentityByID(ctx, entry.ID)
	require.NotNil(t, resolvedIdentity)
	assert.False(t,
		resolvedIdentity.Labels.HasWorldLabel() || resolvedIdentity.Labels.HasWorldIPv4Label(),
		"Identity must not have world label when reserved:host is present. Labels: %v",
		resolvedIdentity.Labels)
}
