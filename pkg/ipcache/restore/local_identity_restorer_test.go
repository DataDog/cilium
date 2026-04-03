// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package restoration

// TestHostIdentityExcludedFromIPCacheRestoration and related tests document the
// restoration filter in dumpOldIPCache that contributes to the host-IP-as-world
// misclassification bug (see pkg/ipcache/metadata_restart_test.go for the full
// reproduction).
//
// The filter at local_identity_restorer.go:128:
//
//   if nid.Scope() == identity.IdentityScopeLocal ||
//      nid == identity.ReservedIdentityIngress {
//       localPrefixes[k.Prefix()] = nid
//   }
//
// ReservedIdentityHost (id=1) has IdentityScopeGlobal (scope bits = 0).
// It does not satisfy either condition and is therefore never included in the
// restored set. After ipcachemap.Recreate() (cell.go:118) wipes the ipcache BPF
// map, host IP entries are absent until syncHostIPs.StartAndWaitFirst() runs
// (daemon.go:249).
//
// If a CiliumCIDRGroup covering the host IP is processed between those two
// points, resolveLabels() in metadata.go receives only the cidrgroup label,
// finds isInCluster=false, and calls AddWorldLabel() — assigning world identity
// to what should be a host IP.

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/identity"
)

// TestHostIdentityExcludedFromIPCacheRestoration documents the restoration
// filter condition that causes host IPs to lose their identity on restart.
// It tests the exact predicate used by dumpOldIPCache at
// local_identity_restorer.go:128.
func TestHostIdentityExcludedFromIPCacheRestoration(t *testing.T) {
	type testCase struct {
		name         string
		id           identity.NumericIdentity
		wantRestored bool
		explanation  string
	}

	cases := []testCase{
		{
			name:         "ReservedIdentityHost is NOT restored",
			id:           identity.ReservedIdentityHost, // id=1, scope=global
			wantRestored: false,
			explanation: "ReservedIdentityHost (id=1) has IdentityScopeGlobal (scope=0). " +
				"It does not satisfy Scope()==IdentityScopeLocal and is not " +
				"ReservedIdentityIngress. Host IP entries are therefore absent from " +
				"the new ipcache BPF map until syncHostIPs runs. If a CiliumCIDRGroup " +
				"covering the host IP is processed during this window, resolveLabels() " +
				"assigns world identity instead of host.",
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
// has global scope — the direct mechanical reason it is excluded from the
// dumpOldIPCache restoration filter and why the world fallback can fire.
func TestHostIdentityScopeIsGlobal(t *testing.T) {
	hostScope := identity.ReservedIdentityHost.Scope()

	assert.Equal(t, identity.IdentityScopeGlobal, hostScope,
		"ReservedIdentityHost must have IdentityScopeGlobal (scope=0). "+
			"This means it is excluded by the dumpOldIPCache filter "+
			"(local_identity_restorer.go:128) which only retains IdentityScopeLocal "+
			"and ReservedIdentityIngress. Host IP entries are therefore absent from "+
			"the new ipcache BPF map after Recreate() until syncHostIPs completes.")

	assert.NotEqual(t, identity.IdentityScopeLocal, hostScope,
		"If this assertion fails, the bug would be self-healing: "+
			"host identity would be restored from the old BPF map and the world fallback "+
			"would not occur during the CiliumCIDRGroup processing window.")
}
