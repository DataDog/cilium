// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ec2

import (
	"errors"
	"net/netip"

	"github.com/cilium/cilium/pkg/ipam/option"
)

type (
	PrefixUsage   [option.ENIPDBlockSizeIPv4]bool
	PrefixesUsage map[netip.Prefix]PrefixUsage
)

var prefixesUsage PrefixesUsage

// ENIPDPrefix returns the /28 prefix for a given IP address
func ENIPDPrefix(addr netip.Addr) (netip.Prefix, error) {
	return addr.Prefix(option.ENIPDBlockBitsSizeIPv4)
}

func IndexInPrefix(addr netip.Addr, prefix netip.Prefix) int {
	return int(addr.AsSlice()[3] - prefix.Addr().AsSlice()[3])

}

func AssignedIP(ip string) error {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return err
	}
	prefix, err := ENIPDPrefix(addr)
	if err != nil {
		return err
	}
	index := IndexInPrefix(addr, prefix)
	if index >= option.ENIPDBlockSizeIPv4 {
		logHADRIEN.Errorf("Index %d too big for IP %s in prefix %s", index, addr, prefix)
		return nil
	}
	prefixUsage := prefixesUsage[prefix]
	prefixUsage[index] = true
	prefixesUsage[prefix] = prefixUsage
	logHADRIEN.WithField("PrefixesUsage", prefixesUsage).Infof("Assigned IP %s from prefix %s", addr, prefix)
	return nil
}

func AssignedIPs(ips []string) error {
	var errs []error
	for _, ip := range ips {
		if err := AssignedIP(ip); err != nil {
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
	prefix, err := ENIPDPrefix(addr)
	if err != nil {
		return err
	}
	index := IndexInPrefix(addr, prefix)
	prefixUsage := prefixesUsage[prefix]
	prefixUsage[index] = false
	prefixesUsage[prefix] = prefixUsage
	logHADRIEN.WithField("PrefixesUsage", prefixesUsage).Infof("Unassigned IP %s from prefix %s", addr, prefix)
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
