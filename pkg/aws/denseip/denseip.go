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
	// prefixUsage represents the usage of IPs within a /28 prefix
	prefixUsage [option.ENIPDBlockSizeIPv4]bool
	// prefixesUsage represents the usage of /28 prefixes within a subnet
	prefixesUsage map[netip.Prefix]*prefixUsage
	// subnetsUsage represents the usage of subnets
	subnetsUsage map[netip.Prefix]*prefixesUsage
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "HADRIEN") //TODO: change

func New() *subnetsUsage {
	return &subnetsUsage{}
}

func (u *subnetsUsage) getPrefixesUsage(subnet netip.Prefix) *prefixesUsage {
	usage := *u
	_, ok := usage[subnet]
	if !ok {
		usage[subnet] = &prefixesUsage{}
		// Mark the AWS subnet reserved addresses as used
		for _, reservedAddr := range awsSubnetReservedAddrs(subnet) {
			if err := u.registerAddrUsed(reservedAddr, subnet); err != nil {
				log.WithError(err).Warnf("Failed to register AWS reserved IP %s as used for subnet %s", reservedAddr, subnet)
			}
		}
	}
	return usage[subnet]
}

// registerAddrUsed registers a given IP address as used within a given subnet
func (u *subnetsUsage) registerAddrUsed(addr netip.Addr, subnet netip.Prefix) error {
	if !subnet.Contains(addr) {
		return fmt.Errorf("IP address %s is not in subnet %s", addr, subnet)
	}
	prefix, index, err := pdPrefixAndIndex(addr)
	if err != nil {
		return err
	}
	u.getPrefixesUsage(subnet).getPrefixUsage(prefix)[index] = true
	// TODO: change to debug log or remove
	log.WithField("subnetsUsage", *u).Infof("Registered: IP %s is used from prefix %s in subnet %s", addr, prefix, subnet)
	return nil
}

// registerAddrUnused registers a given IP address as unused
func (u *subnetsUsage) registerAddrUnused(addr netip.Addr) error {
	usage := *u
	for subnet, prefixesUsage := range usage {
		if !subnet.Contains(addr) {
			continue
		}
		prefix, index, err := pdPrefixAndIndex(addr)
		if err != nil {
			return err
		}
		prefixesUsage.getPrefixUsage(prefix)[index] = false
		// TODO: change to debug log or remove
		log.WithField("subnetsUsage", usage).Infof("Registered: IP %s is unused from prefix %s in subnet %s", addr, prefix, subnet)
		return nil
	}
	return fmt.Errorf("Failed to register address %s as unused because its subnet was not known", addr)
}

func (u *prefixesUsage) getPrefixUsage(prefix netip.Prefix) *prefixUsage {
	usage := *u
	_, ok := usage[prefix]
	if !ok {
		usage[prefix] = &prefixUsage{}
	}
	return usage[prefix]
}

// FindIPs tries to find available IP addresses within a given subnet
func (u *subnetsUsage) FindIPs(subnet netip.Prefix, addressesCount int32) (addresses []string, found bool) {
	prefixesUsage := u.getPrefixesUsage(subnet)
	for prefix, prefixUsage := range *prefixesUsage {
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

// RegisterIPUsed marks an IP as used and logs any error
func (u *subnetsUsage) registerIPUsed(ip string, subnet netip.Prefix) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		log.WithError(err).Debugf("Failed to parse IP %s", ip)
	}
	if err := u.registerAddrUsed(addr, subnet); err != nil {
		log.WithError(err).Debugf("Failed to register IP %s as used", ip)
	}
}

// RegisterIPsUsed marks a list of IPs as used and logs any error
func (u *subnetsUsage) RegisterIPsUsed(ips []string, subnet netip.Prefix) {
	for _, ip := range ips {
		u.registerIPUsed(ip, subnet)
	}
}

// RegisterIPUnused marks an IP as unused and logs any error
func (u *subnetsUsage) registerIPUnused(ip string) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		log.WithError(err).Debugf("Failed to parse IP %s", ip)
	}
	if err := u.registerAddrUnused(addr); err != nil {
		log.WithError(err).Debugf("Failed to register IP %s as unused", ip)
	}
}

// RegisterIPsUnused marks a list of IPs as unused and logs any error
func (u *subnetsUsage) RegisterIPsUnused(ips []string) {
	for _, ip := range ips {
		u.registerIPUnused(ip)
	}
}

// This is the already assigned error from AssignPrivateIpAddresses
var alreadyAssignedError_AssignPrivateIpAddresses_Regexp = regexp.MustCompile(`^\[([^\]]*)\] assigned, but move is not allowed\.$`)

// This is the already assigned error from CreateNetworkInterface
// Sometimes the error is just "The specified address is already in use." but we can't know which address that refers to so we don't register any IP as used from that
var alreadyAssignedError_CreateNetworkInterface_Regexp = regexp.MustCompile(`^([^\s]*) is already assigned\.$`)

func ParseAlreadyAssignedError(assignErr error) []string {
	var apiErr smithy.APIError

	if !errors.As(assignErr, &apiErr) {
		return nil
	}
	errMsg := apiErr.ErrorMessage()
	if matches := alreadyAssignedError_AssignPrivateIpAddresses_Regexp.FindStringSubmatch(errMsg); len(matches) == 2 {
		adressesString := matches[1]
		//TODO: remove
		log.WithError(apiErr).
			WithField("ErrorMessage", apiErr.ErrorMessage()).
			WithField("ErrorCode", apiErr.ErrorCode()).
			Errorf("ERR Smart AssignPrivateIpAddresses failed to assign IPs %v", adressesString)
		return strings.Split(adressesString, ", ")
	}
	if matches := alreadyAssignedError_CreateNetworkInterface_Regexp.FindStringSubmatch(errMsg); len(matches) == 2 {
		address := matches[1]
		//TODO: remove
		log.WithError(apiErr).
			WithField("ErrorMessage", apiErr.ErrorMessage()).
			WithField("ErrorCode", apiErr.ErrorCode()).
			Errorf("ERR Smart CreateNetworkInterface failed to assign IP %v", address)
		return []string{address}
	}
	return nil
}
