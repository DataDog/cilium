// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	current "github.com/containernetworking/cni/pkg/types/100"

	"github.com/cilium/cilium/api/v1/models"
	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"
	"github.com/cilium/cilium/pkg/ip"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func interfaceAdd(ctx context.Context, logger *slog.Logger, ipConfig *current.IPConfig, ipam *models.IPAMAddressResponse, conf *models.DaemonConfigurationStatus) error {
	if ipam == nil {
		return fmt.Errorf("missing IPAM configuration")
	}
	// If the gateway IP is not available, it is already set up
	if ipam.Gateway == "" {
		return nil
	}

	var allCIDRs []*net.IPNet

	for _, cidrString := range ipam.Cidrs {
		_, cidr, err := net.ParseCIDR(cidrString)
		if err != nil {
			return fmt.Errorf("invalid CIDR '%s': %w", cidrString, err)
		}
		allCIDRs = append(allCIDRs, cidr)
	}

	// Coalesce CIDRs into minimum set needed for route rules
	// The routes set up here will be cleaned up by linuxrouting.Delete.
	// Therefor the code here should be kept in sync with the deletion code.
	ipv4CIDRs, ipv6CIDRs := ip.CoalesceCIDRs(allCIDRs)
	coalescedCIDRs := make([]string, 0, len(allCIDRs))
	var masq bool

	if ipConfig.Address.IP.To4() != nil {
		for _, cidr := range ipv4CIDRs {
			coalescedCIDRs = append(coalescedCIDRs, cidr.String())
		}

		masq = conf.MasqueradeProtocols.IPv4
	} else {
		for _, cidr := range ipv6CIDRs {
			coalescedCIDRs = append(coalescedCIDRs, cidr.String())
		}

		masq = conf.MasqueradeProtocols.IPv6
	}

	routingInfo, err := linuxrouting.NewRoutingInfo(
		logger,
		ipam.Gateway,
		coalescedCIDRs,
		ipam.MasterMac,
		ipam.InterfaceNumber,
		conf.IpamMode,
		masq,
	)
	if err != nil {
		return fmt.Errorf("unable to parse routing info: %w", err)
	}

	// Otherwise Configure can transiently fail CNI ADD with "interface with MAC ... not found",
	// leaving the pod stuck in ContainerCreating.
	if conf.IpamMode == ipamOption.IPAMENI {
		if err := linuxrouting.WaitForENIInterface(ctx, routingInfo.MasterIfMAC); err != nil {
			logger.Warn(
				"Unable to find ENI netlink interface, this will likely lead to an error configuring the pod's IP rules and routes",
				logfields.MACAddr, routingInfo.MasterIfMAC,
				logfields.Error, err,
			)
		}
	}

	if err := routingInfo.Configure(
		ipConfig.Address.IP,
		int(conf.DeviceMTU),
		false,
	); err != nil {
		return fmt.Errorf("unable to install ip rules and routes: %w", err)
	}

	return nil
}
