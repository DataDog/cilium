// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package denseip

import (
	"net/netip"
	"testing"
)

func TestIndexInPrefix(t *testing.T) {
	tests := []struct {
		addr   netip.Addr
		prefix netip.Prefix
		want   int
	}{
		{
			addr:   netip.MustParseAddr("192.168.1.5"),
			prefix: netip.MustParsePrefix("192.168.1.0/24"),
			want:   5,
		},
		{
			addr:   netip.MustParseAddr("192.168.1.10"),
			prefix: netip.MustParsePrefix("192.168.1.0/24"),
			want:   10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.addr.String(), func(t *testing.T) {
			if got := indexInPrefix(tt.addr, tt.prefix); got != tt.want {
				t.Errorf("indexInPrefix() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestEniPrefixDelegationPrefix(t *testing.T) {
	tests := []struct {
		addr netip.Addr
		want string
	}{
		{
			addr: netip.MustParseAddr("192.168.1.5"),
			want: "192.168.1.0/28",
		},
		{
			addr: netip.MustParseAddr("10.0.0.18"),
			want: "10.0.0.16/28",
		},
	}

	for _, tt := range tests {
		t.Run(tt.addr.String(), func(t *testing.T) {
			prefix, err := eniPrefixDelegationPrefix(tt.addr)
			if err != nil {
				t.Fatalf("eniPrefixDelegationPrefix() returned error: %v", err)
			}
			if got := prefix.String(); got != tt.want {
				t.Errorf("eniPrefixDelegationPrefix() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestAddrInPrefix(t *testing.T) {
	tests := []struct {
		prefix netip.Prefix
		index  int
		want   netip.Addr
	}{
		{
			prefix: netip.MustParsePrefix("192.168.1.0/24"),
			index:  5,
			want:   netip.MustParseAddr("192.168.1.5"),
		},
		{
			prefix: netip.MustParsePrefix("192.168.1.0/24"),
			index:  10,
			want:   netip.MustParseAddr("192.168.1.10"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.want.String(), func(t *testing.T) {
			if got := addrInPrefix(tt.prefix, tt.index); got != tt.want {
				t.Errorf("addrInPrefix() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestBroadcastAddr(t *testing.T) {
	tests := []struct {
		name     string
		subnet   string
		expected string
	}{
		{
			name:     "Test /24 subnet",
			subnet:   "192.168.1.0/24",
			expected: "192.168.1.255",
		},
		{
			name:     "Test /16 subnet",
			subnet:   "172.16.0.0/16",
			expected: "172.16.255.255",
		},
		{
			name:     "Test /8 subnet",
			subnet:   "10.0.0.0/8",
			expected: "10.255.255.255",
		},
		{
			name:     "Test /30 subnet",
			subnet:   "192.168.1.4/30",
			expected: "192.168.1.7",
		},
		{
			name:     "Test /32 subnet (single host)",
			subnet:   "192.168.1.10/32",
			expected: "192.168.1.10",
		},
		{
			name:     "Test /29 subnet",
			subnet:   "192.168.1.8/29",
			expected: "192.168.1.15",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix, err := netip.ParsePrefix(tt.subnet)
			if err != nil {
				t.Fatalf("failed to parse subnet %s: %v", tt.subnet, err)
			}

			broadcast := broadcastAddr(prefix)
			if broadcast.String() != tt.expected {
				t.Errorf("broadcastAddr(%s) = %s; want %s", tt.subnet, broadcast, tt.expected)
			}
		})
	}
}
