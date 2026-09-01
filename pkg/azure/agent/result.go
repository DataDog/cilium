// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"fmt"
	"net/netip"
	"slices"

	"go4.org/netipx"

	azureTypes "github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipmasq"
	"github.com/cilium/cilium/pkg/option"
)

func allocationResult(
	allocatedAddr netip.Addr,
	pool ipam.Pool,
	interfaces []azureTypes.AzureInterface,
	conf *option.DaemonConfig,
	ipMasqAgent *ipmasq.IPMasqAgent,
) (*ipam.AllocationResult, error) {
	for _, iface := range interfaces {
		if !slices.ContainsFunc(iface.Addresses, func(address azureTypes.AzureAddress) bool {
			return address.State == azureTypes.StateSucceeded && address.IP.Addr == allocatedAddr
		}) {
			continue
		}

		result := &ipam.AllocationResult{
			IP:              allocatedAddr,
			IPPoolName:      pool,
			PrimaryMAC:      iface.MAC,
			InterfaceNumber: "0",
		}
		if iface.Gateway.IsValid() {
			result.GatewayIP = iface.Gateway.Addr
		}
		if prefix := azureInterfaceCIDR(iface); prefix.IsValid() {
			result.CIDRs = append(result.CIDRs, prefix)
		}
		if allocatedAddr.Is4() && conf.EnableIPv4 && conf.IPv4NativeRoutingCIDR != nil {
			if prefix, ok := netipx.FromStdIPNet(conf.IPv4NativeRoutingCIDR.IPNet); ok {
				result.CIDRs = append(result.CIDRs, prefix)
			}
		}
		if conf.EnableIPMasqAgent {
			for _, prefix := range ipMasqAgent.NonMasqCIDRsFromConfig() {
				if allocatedAddr.Is4() == prefix.Addr().Is4() {
					result.CIDRs = append(result.CIDRs, prefix)
				}
			}
		}

		return result, nil
	}

	return nil, fmt.Errorf("unable to find Azure interface for IP %s", allocatedAddr)
}
