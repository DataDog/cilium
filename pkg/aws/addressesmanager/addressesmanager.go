// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package addressesmanager

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	ec2_types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
	"go4.org/netipx"

	"github.com/cilium/cilium/pkg/ipam/option"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/lock"
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

	addressesManager struct {
		mutex        lock.Mutex
		subnetsUsage *subnetsUsage
	}
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "HADRIEN") //TODO: change

func New(subnets ipamTypes.SubnetMap, networkInterfaces []ec2_types.NetworkInterface) *addressesManager {
	a := &addressesManager{
		subnetsUsage: &subnetsUsage{},
	}

	// Prepopulate a.subnetsUsage with the current usage of subnets
	for _, networkInterface := range networkInterfaces {
		for _, privateIp := range networkInterface.PrivateIpAddresses {
			addr, err := netip.ParseAddr(*privateIp.PrivateIpAddress)
			if err != nil {
				log.WithError(err).Warnf("Failed to parse IP %s", *privateIp.PrivateIpAddress)
				continue
			}
			subnetCIDR := subnets[*networkInterface.SubnetId].CIDR
			subnet, ok := netipx.FromStdIPNet(subnetCIDR.IPNet)
			if !ok {
				log.Warnf("Failed to parse subnet CIDR %v", subnetCIDR)
				continue
			}
			a.registerAddrUsed(addr, subnet)
		}
	}
	return a
}

func (a *addressesManager) getPrefixesUsage(subnet netip.Prefix) *prefixesUsage {
	_, ok := (*a.subnetsUsage)[subnet]
	if !ok {
		// That subnet has not yet been seen
		(*a.subnetsUsage)[subnet] = &prefixesUsage{}

		// Mark the AWS subnet reserved addresses as used
		for _, reservedAddr := range awsSubnetReservedAddrs(subnet) {
			if err := a.registerAddrUsed(reservedAddr, subnet); err != nil {
				log.WithError(err).Warnf("Failed to register AWS reserved IP %s as used for subnet %s", reservedAddr, subnet)
			}
		}
	}
	return (*a.subnetsUsage)[subnet]
}

// registerAddrUsed registers a given IP address as used within a given subnet
func (a *addressesManager) registerAddrUsed(addr netip.Addr, subnet netip.Prefix) error {
	if !subnet.Contains(addr) {
		return fmt.Errorf("IP address %s is not in subnet %s", addr, subnet)
	}
	prefix, index, err := pdPrefixAndIndex(addr)
	if err != nil {
		return err
	}

	// a.mutex.Lock()
	// defer a.mutex.Unlock()

	a.getPrefixesUsage(subnet).getPrefixUsage(prefix)[index] = true
	// TODO: change to debug log or remove
	log.WithField("subnetsUsage", *a.subnetsUsage).Infof("Registered: IP %s is used from prefix %s in subnet %s", addr, prefix, subnet)
	return nil
}

// registerAddrUnused registers a given IP address as unused
func (a *addressesManager) registerAddrUnused(addr netip.Addr) error {
	// a.mutex.Lock()
	// defer a.mutex.Unlock()

	for subnet, prefixesUsage := range *a.subnetsUsage {
		if !subnet.Contains(addr) {
			continue
		}
		prefix, index, err := pdPrefixAndIndex(addr)
		if err != nil {
			return err
		}
		prefixesUsage.getPrefixUsage(prefix)[index] = false
		// TODO: change to debug log or remove
		log.WithField("subnetsUsage", *a.subnetsUsage).Infof("Registered: IP %s is unused from prefix %s in subnet %s", addr, prefix, subnet)
		return nil
	}
	return fmt.Errorf("Failed to register address %s as unused because its subnet was not known", addr)
}

func (u *prefixesUsage) getPrefixUsage(prefix netip.Prefix) *prefixUsage {
	_, ok := (*u)[prefix]
	if !ok {
		(*u)[prefix] = &prefixUsage{}
	}
	return (*u)[prefix]
}

// FindIPs tries to find available IP addresses within a given subnet
// It starts by filling the first and last prefixes of the subnet as those contain AWS reserved IPs
// and hence are never assignable through prefix delegation
// Then once those are fully assigned, it assigns from the /28 prefixes that have the least available IPs
func (a *addressesManager) FindIPs(subnet netip.Prefix, addressesCount int32) (addresses []string, found bool) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	reservedPrefixes := []netip.Prefix{}
	// prefixesByAvailableIPs is a list of prefixesUsage by number of free IPs
	// i.e. prefixesByAvailableIPs[n] is a *prefixesUsage of prefixes with n available IPs
	//
	// prefixesByAvailableIPs[0] is special as it contains the first and last prefixes of the subnet regardless
	// of their number of available IPs to ensure they have priority
	prefixesByAvailableIPs := make([]*prefixesUsage, option.ENIPDBlockSizeIPv4)

	for prefix, prefixUsage := range *a.getPrefixesUsage(subnet) {
		availableIPsInPrefix := option.ENIPDBlockSizeIPv4

		// Handle the prefixes containing reserved IPS
		if slices.Contains(reservedPrefixes, prefix) {
			availableIPsInPrefix = 0
		} else {

			for _, used := range prefixUsage {
				if used {
					availableIPsInPrefix--
				}
				// if len(addresses) == int(addressesCount) {
				// 	return addresses, true
				// }
				// if !used {
				// 	addr := addrInPrefix(prefix, index).String()
				// 	addresses = append(addresses, addr)
				// }
			}
		}
		// If there are no available IPs in the prefix, we skip it
		// This means prefixesByAvailableIPs[0] is always empty
		// if availableIPsInPrefix == 0 {
		// 	continue
		// }
		if prefixesByAvailableIPs[availableIPsInPrefix] == nil {
			prefixesByAvailableIPs[availableIPsInPrefix] = &prefixesUsage{}
		}
		usage := *prefixesByAvailableIPs[availableIPsInPrefix]
		usage[prefix] = prefixUsage
	}

	// Now that we have sorted prefixes by available IPs, we pick IPs from the most assigned from first
	for availableCount, prefixesUsage := range prefixesByAvailableIPs {
		if prefixesUsage == nil {
			continue
		}
		for prefix, prefixUsage := range *prefixesUsage {
			for index, used := range prefixUsage {
				if len(addresses) == int(addressesCount) {
					return addresses, true
				}
				if !used {
					addr := addrInPrefix(prefix, index).String()
					log.WithField("prefixesByAvailableIPs", prefixesByAvailableIPs).Infof("Picking IP %s from prefix %s that currently has %d available IPs", addr, prefix, availableCount)
					addresses = append(addresses, addr)
				}
			}
		}

	}
	log.Warnf("Failed to find %d available IPs in subnet %s, only found %d", addressesCount, subnet, len(addresses))
	return nil, false
}

// RegisterIPUsed marks an IP as used and logs any error
func (a *addressesManager) registerIPUsed(ip string, subnet netip.Prefix) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		log.WithError(err).Debugf("Failed to parse IP %s", ip)
	}
	if err := a.registerAddrUsed(addr, subnet); err != nil {
		log.WithError(err).Debugf("Failed to register IP %s as used", ip)
	}
}

// RegisterIPsUsed marks a list of IPs as used and logs any error
func (a *addressesManager) RegisterIPsUsed(ips []string, subnet netip.Prefix) {
	for _, ip := range ips {
		a.registerIPUsed(ip, subnet)
	}
}

// RegisterIPUnused marks an IP as unused and logs any error
func (a *addressesManager) registerIPUnused(ip string) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		log.WithError(err).Debugf("Failed to parse IP %s", ip)
	}
	if err := a.registerAddrUnused(addr); err != nil {
		log.WithError(err).Debugf("Failed to register IP %s as unused", ip)
	}
}

// RegisterIPsUnused marks a list of IPs as unused and logs any error
func (a *addressesManager) RegisterIPsUnused(ips []string) {
	for _, ip := range ips {
		a.registerIPUnused(ip)
	}
}

// This is the already assigned error from AssignPrivateIpAddresses
var alreadyAssignedError_AssignPrivateIpAddresses_Regexp = regexp.mustcompile(`^\[([^\]]*)\] assigned, but move is not allowed\.$`)

// This is the already assigned error from CreateNetworkInterface
// Sometimes the error is just "The specified address is already in use." but we can't know which address that refers to so we don't register any IP as used from that
var alreadyAssignedError_CreateNetworkInterface_Regexp = regexp.MustCompile(`^([^\s]*) is already assigned\.$`)

// TODO: use this slice once we remove the temp telemetry
// var alreadyAssignedErrorRegexps = []*regexp.Regexp{
//     // This is the already assigned error returned by the AssignPrivateIpAddresses method
//     regexp.mustcompile(`^\[([^\]]*)\] assigned, but move is not allowed\.$`),

//     // This is the already assigned error returned by the CreateNetworkInterface method
//     // Sometimes the CreateNetworkInterface method returns a more generic "The specified address is already in use."
//     // error, but there is no useful information to extract from such errors
//     regexp.MustCompile(`^([^\s]*) is already assigned\.$`),
// }

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
