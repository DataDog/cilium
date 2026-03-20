// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package restoration

// TestHostIdentityExcludedFromIPCacheRestoration tests that the ipcache
// restoration logic (dumpOldIPCache) explicitly excludes ReservedIdentityHost
// entries from the set of identities that survive an agent restart.
//
// This is one of two root causes for the host-IP-as-world misclassification bug:
//
//   dumpOldIPCache() at local_identity_restorer.go:128:
//
//     if nid.Scope() == identity.IdentityScopeLocal ||
//        nid == identity.ReservedIdentityIngress {
//         localPrefixes[k.Prefix()] = nid  // host identity NEVER matches
//     }
//
// Because ReservedIdentityHost (id=1) has IdentityScopeGlobal (scope bits = 0),
// it does not pass the IdentityScopeLocal check. It is also not
// ReservedIdentityIngress. The host IP entry from the OLD ipcache BPF map is
// therefore NEVER written into localPrefixes and is NEVER restored into the new
// ipcache metadata.
//
// Consequence: after ipcachemap.Recreate() wipes the BPF map (cell.go:118),
// there is a window before syncHostIPs runs (daemon.go:249) during which host
// IPs have no ipcache metadata entry. If a CiliumCIDRGroup covering the host IP
// is processed during this window, resolveLabels() sees only the cidrgroup label,
// calls AddWorldLabel(), and assigns world identity — causing policy_denied drops.

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/identity"
)

// TestHostIdentityExcludedFromIPCacheRestoration documents the restoration
// filter condition that causes host IPs to lose their identity on restart.
//
// The filter in dumpOldIPCache (local_identity_restorer.go:128) is:
//
//	nid.Scope() == identity.IdentityScopeLocal || nid == identity.ReservedIdentityIngress
//
// This test verifies the scope/identity values used by the filter and shows
// which identities are retained vs dropped during restoration.
func TestHostIdentityExcludedFromIPCacheRestoration(t *testing.T) {
	type testCase struct {
		name           string
		id             identity.NumericIdentity
		wantRestored   bool
		explanation    string
	}

	// These cases mirror the exact filter condition at local_identity_restorer.go:128.
	cases := []testCase{
		{
			name:         "ReservedIdentityHost is NOT restored",
			id:           identity.ReservedIdentityHost, // id=1, scope=global
			wantRestored: false,
			explanation: "ReservedIdentityHost (id=1) has IdentityScopeGlobal (scope bits = 0). " +
				"It does not satisfy Scope()==IdentityScopeLocal and is not ReservedIdentityIngress. " +
				"BUG: after ipcachemap.Recreate(), host IP entries are missing from the new ipcache " +
				"until syncHostIPs runs. If CiliumCIDRGroup processing happens first, " +
				"resolveLabels() assigns world identity to the host IP.",
		},
		{
			name:         "ReservedIdentityWorld is NOT restored",
			id:           identity.ReservedIdentityWorld, // id=2, scope=global
			wantRestored: false,
			explanation:  "World identity is re-added as a /0 catch-all by syncHostIPs, not via restoration.",
		},
		{
			name:         "ReservedIdentityIngress IS restored",
			id:           identity.ReservedIdentityIngress,
			wantRestored: true,
			explanation:  "Ingress is explicitly included via the nid==ReservedIdentityIngress check.",
		},
		{
			name:         "A local-scope CIDR identity IS restored",
			id:           identity.NumericIdentity(1<<24 + 42), // IdentityScopeLocal | 42
			wantRestored: true,
			explanation: "Local-scope CIDR identities are restored to preserve numeric identity " +
				"stability across restarts. This is the primary use case for dumpOldIPCache.",
		},
		{
			name:         "A remote-node-scope identity is NOT restored",
			id:           identity.NumericIdentity(2<<24 + 1), // IdentityScopeRemoteNode | 1
			wantRestored: false,
			explanation:  "Remote-node-scope identities are re-derived from the node manager, not restored.",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// This is the exact filter predicate from dumpOldIPCache:
			//   local_identity_restorer.go:128
			wouldBeRestored := tc.id.Scope() == identity.IdentityScopeLocal ||
				tc.id == identity.ReservedIdentityIngress

			assert.Equal(t, tc.wantRestored, wouldBeRestored,
				"%s\n"+
					"  identity id:    %d\n"+
					"  identity scope: %d (IdentityScopeLocal=%d, IdentityScopeGlobal=%d)\n"+
					"  filter result:  restored=%v",
				tc.explanation,
				tc.id,
				tc.id.Scope(),
				identity.IdentityScopeLocal,
				identity.IdentityScopeGlobal,
				wouldBeRestored,
			)
		})
	}
}

// TestHostIdentityScopeIsGlobal explicitly verifies that ReservedIdentityHost
// has global scope, which is why it is excluded from the restoration filter.
// This is the direct mechanical reason for the misclassification bug.
func TestHostIdentityScopeIsGlobal(t *testing.T) {
	hostScope := identity.ReservedIdentityHost.Scope()

	assert.Equal(t, identity.IdentityScopeGlobal, hostScope,
		"ReservedIdentityHost must have IdentityScopeGlobal (scope=0). "+
			"This means it is excluded by the dumpOldIPCache filter "+
			"(local_identity_restorer.go:128) which only retains IdentityScopeLocal "+
			"and ReservedIdentityIngress. As a result, host IP entries are lost from "+
			"the ipcache BPF map after ipcachemap.Recreate() and are not re-inserted "+
			"until syncHostIPs.StartAndWaitFirst() completes (daemon.go:249).")

	assert.NotEqual(t, identity.IdentityScopeLocal, hostScope,
		"If this assertion fails, the bug would be self-healing: "+
			"host identity would be restored and the world fallback would not occur.")
}
