// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ec2

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/cilium/pkg/ipam/option"
)

type (
	PrefixUsage   []bool
	PrefixesUsage map[netip.Prefix]PrefixUsage
)

//var prefixesUsage = make(map[netip.Prefix]PrefixUsage)

// Nested structure subnet -> /28 prefix -> IP
var subnetsUsage = make(map[netip.Prefix]map[netip.Prefix][]bool)

// ENIPrefixDelegationPrefix returns the /28 prefix for a given IP address
func ENIPrefixDelegationPrefix(addr netip.Addr) (netip.Prefix, error) {
	return addr.Prefix(option.ENIPDBlockBitsSizeIPv4)
}

func IndexInPrefix(addr netip.Addr, prefix netip.Prefix) int {
	return int(addr.AsSlice()[3] - prefix.Addr().AsSlice()[3])
}

func AddrInPrefix(prefix netip.Prefix, index int) netip.Addr {
	addr := prefix.Addr()
	for i := 0; i < index; i++ {
		addr = addr.Next()
	}
	return addr
}

func AssignedIP(ip string, subnet netip.Prefix) error {
	prefixesUsage, ok := subnetsUsage[subnet]
	if !ok {
		prefixesUsage = make(map[netip.Prefix][]bool)
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return err
	}
	if !subnet.Contains(addr) {
		return fmt.Errorf("IP %s is not in subnet %s", addr, subnet)
	}
	prefix, err := ENIPrefixDelegationPrefix(addr)
	if err != nil {
		return err
	}
	index := IndexInPrefix(addr, prefix)
	if index >= option.ENIPDBlockSizeIPv4 {
		return fmt.Errorf("Index %d too big for IP %s in prefix %s", index, addr, prefix)
	}
	prefixUsage, ok := prefixesUsage[prefix]
	if !ok {
		prefixUsage = make([]bool, option.ENIPDBlockSizeIPv4)
	}
	prefixUsage[index] = true
	prefixesUsage[prefix] = prefixUsage
	subnetsUsage[subnet] = prefixesUsage
	logHADRIEN.WithField("subnetsUsage", subnetsUsage).Infof("Registered: IP %s is used from prefix %s in subnet %s", addr, prefix, subnet)
	return nil
}

func AssignedIPs(ips []string, subnet netip.Prefix) error {
	var errs []error
	for _, ip := range ips {
		if err := AssignedIP(ip, subnet); err != nil {
			errs = append(errs, err)
			continue
		}
	}
	return errors.Join(errs...)
}

func UnassignedIP(ip string) error {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return err
	}

	var subnet netip.Prefix
	prefixesUsage := make(map[netip.Prefix][]bool)
	for s, u := range subnetsUsage {
		if s.Contains(addr) {
			subnet = s
			prefixesUsage = u
		}
	}
	prefix, err := ENIPrefixDelegationPrefix(addr)
	if err != nil {
		return err
	}
	index := IndexInPrefix(addr, prefix)
	prefixUsage, ok := prefixesUsage[prefix]
	if !ok {
		prefixUsage = make([]bool, option.ENIPDBlockSizeIPv4)
	}
	prefixUsage[index] = false
	prefixesUsage[prefix] = prefixUsage
	subnetsUsage[subnet] = prefixesUsage
	logHADRIEN.WithField("subnetsUsage", subnetsUsage).Infof("Registered:IP %s is unused from prefix %s in subnet %s", addr, prefix, subnet)
	return nil
}

func UnassignedIPs(ips []string) error {
	var errs []error
	for _, ip := range ips {
		if err := UnassignedIP(ip); err != nil {
			errs = append(errs, err)
			continue
		}
	}
	return errors.Join(errs...)
}

func FindIPs(subnet netip.Prefix, addressesCount int32) (addresses []string, found bool) {
	prefixesUsage := make(map[netip.Prefix][]bool)
	if u, ok := subnetsUsage[subnet]; ok {
		prefixesUsage = u
	}

	for prefix, prefixUsage := range prefixesUsage {
		for index, used := range prefixUsage {
			if !used && len(addresses) < int(addressesCount) {
				addr := AddrInPrefix(prefix, index).String()
				logHADRIEN.WithField("subnetsUsage", subnetsUsage).Infof("Found potentially available IP %s from prefix %s in subnet %s", addr, prefix, subnet)
				addresses = append(addresses, addr)
			}
		}
	}
	if len(addresses) != int(addressesCount) {
		logHADRIEN.WithField("subnetsUsage", subnetsUsage).Infof("Failed to find %d available IPs in subnet %s, only found %d", addressesCount, subnet, len(addresses))
		return nil, false
	}
	logHADRIEN.WithField("subnetsUsage", subnetsUsage).Infof("Found %d potentially available IPs in subnet %s: %v", len(addresses), subnet, addresses)
	return addresses, true
}
