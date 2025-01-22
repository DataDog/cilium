// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package denseip

import (
	"net/netip"
	"testing"
)

func TestIndexInPrefix(t *testing.T) {
	tests := []struct {
		addr     netip.Addr
		prefix   netip.Prefix
		expected int
	}{
		{
			addr:     netip.MustParseAddr("192.168.1.5"),
			prefix:   netip.MustParsePrefix("192.168.1.0/24"),
			expected: 5,
		},
		{
			addr:     netip.MustParseAddr("192.168.1.10"),
			prefix:   netip.MustParsePrefix("192.168.1.0/24"),
			expected: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.addr.String(), func(t *testing.T) {
			if got := indexInPrefix(tt.addr, tt.prefix); got != tt.expected {
				t.Errorf("indexInPrefix() = %d, expected %d", got, tt.expected)
			}
		})
	}
}

func TestPDPrefixAndIndex(t *testing.T) {
	tests := []struct {
		addr           netip.Addr
		expectedPrefix string
		expectedIndex  int
		expectedErr    error
	}{
		{
			addr:           netip.MustParseAddr("192.168.1.5"),
			expectedPrefix: "192.168.1.0/28",
			expectedIndex:  5,
		},
		{
			addr:           netip.MustParseAddr("10.0.0.20"),
			expectedPrefix: "10.0.0.16/28",
			expectedIndex:  4,
		},
	}

	for _, tt := range tests {
		prefix, index, err := pdPrefixAndIndex(tt.addr)
		if prefix.String() != tt.expectedPrefix || index != tt.expectedIndex || err != tt.expectedErr {
			t.Errorf("pdPrefixAndIndex(%s) = (%v, %d, %v), expected (%v, %d, %v)", tt.addr, prefix, index, err, tt.expectedPrefix, tt.expectedIndex, tt.expectedErr)
		}
	}
}

func TestAddrInPrefix(t *testing.T) {
	tests := []struct {
		prefix   netip.Prefix
		index    int
		expected netip.Addr
	}{
		{
			prefix:   netip.MustParsePrefix("192.168.1.0/24"),
			index:    5,
			expected: netip.MustParseAddr("192.168.1.5"),
		},
		{
			prefix:   netip.MustParsePrefix("192.168.1.0/24"),
			index:    10,
			expected: netip.MustParseAddr("192.168.1.10"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.expected.String(), func(t *testing.T) {
			if got := addrInPrefix(tt.prefix, tt.index); got != tt.expected {
				t.Errorf("addrInPrefix() = %s, want %s", got, tt.expected)
			}
		})
	}
}
