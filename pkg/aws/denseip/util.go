// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package denseip

import "net/netip"

// eniPrefixDelegationPrefix returns the /28 prefix for a given IP address
func eniPrefixDelegationPrefix(addr netip.Addr) (netip.Prefix, error) {
	return addr.Prefix(28)
}

// indexInPrefix returns the index of the IP address in the prefix
func indexInPrefix(addr netip.Addr, prefix netip.Prefix) int {
	return int(addr.AsSlice()[3] - prefix.Addr().AsSlice()[3])
}

// addrInPrefix returns the IP address at the given index in the prefix
func addrInPrefix(prefix netip.Prefix, index int) netip.Addr {
	addr := prefix.Addr()
	for i := 0; i < index; i++ {
		addr = addr.Next()
	}
	return addr
}

const maxByte = 255
const bitsPerByte = 8

func addrToInt(addr netip.Addr) (addrInt int) {
	addrBytes := addr.AsSlice()
	addrBytesCount := len(addrBytes)
	for i := 0; i < addrBytesCount; i++ {
		addrInt += int(addrBytes[i]) << ((addrBytesCount - 1 - i) * bitsPerByte)
	}
	return addrInt
}

func intToV4Addr(addrInt int) (addr netip.Addr) {
	addrBytes := [4]byte{}
	for i := 0; i < 4; i++ {
		// Mask the appropriate 8 bits and shift right by the appropiate number of bits
		mask := maxByte << (i * bitsPerByte)
		maskedAndShifted := (addrInt & mask) >> (i * bitsPerByte)
		addrBytes[3-i] = byte(maskedAndShifted)
	}
	return netip.AddrFrom4(addrBytes)
}

func broadcastAddr(subnet netip.Prefix) netip.Addr {
	subnetAddr := subnet.Masked().Addr()
	subnetBits := subnet.Bits()
	subnetAddrInt := addrToInt(subnetAddr)
	broadcastAddrInt := subnetAddrInt | ((1 << (32 - subnetBits)) - 1)
	return intToV4Addr(broadcastAddrInt)
}
