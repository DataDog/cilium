// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Currently only supports IPv4
package denseip

import (
	"fmt"
	"net/netip"

	"go4.org/netipx"

	"github.com/cilium/cilium/pkg/ipam/option"
)

// eniPDPrefix returns the /28 prefix for a given IP address
func eniPDPrefix(addr netip.Addr) (netip.Prefix, error) {
	return addr.Prefix(option.ENIPDBlockBitsSizeIPv4)
}

// indexInPrefix returns the index of the IP address in the prefix
func indexInPrefix(addr netip.Addr, prefix netip.Prefix) int {
	return int(addr.AsSlice()[3] - prefix.Addr().AsSlice()[3])
}

// prefixAndIndex returns the /28 prefix and index of the IP address in that prefix
func pdPrefixAndIndex(addr netip.Addr) (netip.Prefix, int, error) {
	prefix, err := eniPDPrefix(addr)
	if err != nil {
		return netip.Prefix{}, 0, err
	}

	addrIndex := int(addr.AsSlice()[3] - prefix.Addr().AsSlice()[3])

	if addrIndex >= option.ENIPDBlockSizeIPv4 {
		return netip.Prefix{}, 0, fmt.Errorf("Index %d out of bounds for IP %s in prefix %s", addrIndex, addr, prefix)
	}

	return prefix, addrIndex, nil
}

// addrInPrefix returns the IP address at the given index in the prefix
func addrInPrefix(prefix netip.Prefix, index int) netip.Addr {
	addr := prefix.Addr()
	for i := 0; i < index; i++ {
		addr = addr.Next()
	}
	return addr
}

// See https://docs.aws.amazon.com/vpc/latest/userguide/subnet-sizing.html#subnet-sizing-ipv4
func awsSubnetReservedAddrs(subnet netip.Prefix) (reservedAddrs []netip.Addr) {
	reservedAddr := subnet.Masked().Addr()
	// The first 4 addresses and the last address of each subnet are reserved by AWS
	for i := 0; i < 4; i++ {
		reservedAddrs = append(reservedAddrs, reservedAddr)
		reservedAddr = reservedAddr.Next()
	}
	reservedAddrs = append(reservedAddrs, netipx.PrefixLastIP(subnet))
	return reservedAddrs
}
