// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package denseip

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/aws/smithy-go"
	"github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type (
	// PrefixUsage represents the usage of IPs within a /28 prefix
	PrefixUsage [option.ENIPDBlockSizeIPv4]bool
	// PrefixesUsage represents the usage of /28 prefixes within a subnet
	PrefixesUsage map[netip.Prefix]*PrefixUsage
	// SubnetsUsage represents the usage of subnets
	SubnetsUsage map[netip.Prefix]*PrefixesUsage
)

var subnetsUsage = &SubnetsUsage{}
var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "HADRIEN") //TODO: change

func (u *SubnetsUsage) getPrefixesUsage(subnet netip.Prefix) *PrefixesUsage {
	usage := *u
	_, ok := usage[subnet]
	if !ok {
		usage[subnet] = &PrefixesUsage{}
		// Mark the AWS subnet reserved addresses as used
		for _, reservedAddr := range awsSubnetReservedAddrs(subnet) {
			if err := u.markUsed(reservedAddr, subnet); err != nil {
				fmt.Printf("%v", err) // TODO: handle error
			}
		}
	}
	return usage[subnet]
}

// markUsed registers a given IP address as used within a given subnet
func (u *SubnetsUsage) markUsed(addr netip.Addr, subnet netip.Prefix) error {
	if !subnet.Contains(addr) {
		return fmt.Errorf("IP address %s is not in subnet %s", addr, subnet)
	}
	prefix, err := eniPrefixDelegationPrefix(addr)
	if err != nil {
		return err
	}
	index := indexInPrefix(addr, prefix)
	if index >= option.ENIPDBlockSizeIPv4 {
		return fmt.Errorf("Index %d too out of bounds for IP %s in prefix %s", index, addr, prefix)
	}
	u.getPrefixesUsage(subnet).getPrefixUsage(prefix)[index] = true
	log.WithField("subnetsUsage", subnetsUsage).Infof("Registered: IP %s is used from prefix %s in subnet %s", addr, prefix, subnet)
	return nil
}

// markUnused registers a given IP address as unused
func (u *SubnetsUsage) markUnused(addr netip.Addr) error {
	usage := *u
	for subnet, prefixesUsage := range usage {
		if !subnet.Contains(addr) {
			continue
		}
		prefix, err := eniPrefixDelegationPrefix(addr)
		if err != nil {
			return err
		}
		index := indexInPrefix(addr, prefix)
		if index >= option.ENIPDBlockSizeIPv4 {
			return fmt.Errorf("Index %d too out of bounds for IP %s in prefix %s", index, addr, prefix)
		}
		prefixesUsage.getPrefixUsage(prefix)[index] = false
		log.WithField("subnetsUsage", subnetsUsage).Infof("Registered: IP %s is unused from prefix %s in subnet %s", addr, prefix, subnet)
		return nil
	}
	return fmt.Errorf("Failed to register address %s as unused because its subnet was not known", addr)
}

func (u *PrefixesUsage) getPrefixUsage(prefix netip.Prefix) *PrefixUsage {
	usage := *u
	_, ok := usage[prefix]
	if !ok {
		usage[prefix] = &PrefixUsage{}
	}
	return usage[prefix]
}

// FindIPs tries to find available IP addresses within a given subnet
func FindIPs(subnet netip.Prefix, addressesCount int32) (addresses []string, found bool) {
	prefixesUsage := *subnetsUsage.getPrefixesUsage(subnet)
	for prefix, prefixUsage := range prefixesUsage {
		for index, used := range prefixUsage {
			if len(addresses) == int(addressesCount) {
				return addresses, true
			}
			if !used {
				addr := addrInPrefix(prefix, index).String()
				addresses = append(addresses, addr)
			}
		}
	}
	log.Warnf("Failed to find %d available IPs in subnet %s, only found %d", addressesCount, subnet, len(addresses))
	return nil, false
}

func AssignedIP(ip string, subnet netip.Prefix) error {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return err
	}
	return subnetsUsage.markUsed(addr, subnet)
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
	return subnetsUsage.markUnused(addr)
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

var alreadyAssignedErrorRegexp = regexp.MustCompile(`^\[([^\]]*)\] assigned, but move is not allowed\.$`)

func ParseAlreadyAssignedError(err error) []string {
	var apiErr smithy.APIError

	if !errors.As(err, &apiErr) {
		return nil
	}
	errMsg := apiErr.ErrorMessage()
	matches := alreadyAssignedErrorRegexp.FindStringSubmatch(errMsg)
	if len(matches) != 2 {
		return nil
	}
	adressesString := matches[1]
	log.Errorf("ERR Smart AssignPrivateIpAddresses failed to assign IPs %v", adressesString)
	return strings.Split(adressesString, ", ")
}

// See https://docs.aws.amazon.com/vpc/latest/userguide/subnet-sizing.html#subnet-sizing-ipv4
func awsSubnetReservedAddrs(subnet netip.Prefix) (reservedAddrs []netip.Addr) {
	reservedAddr := subnet.Masked().Addr()
	for i := 0; i < 4; i++ {
		// The first 4 addresses and the last address of each subnet are reserved by AWS
		reservedAddrs = append(reservedAddrs, reservedAddr)
		reservedAddr = reservedAddr.Next()
	}
	reservedAddrs = append(reservedAddrs, broadcastAddr(subnet))
	return reservedAddrs
}
