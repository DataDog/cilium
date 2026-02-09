// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam/service/ipallocator"
)

// routingInfo caches the auto-detected routing information for the allocation
// CIDR. nil when no matching interface was found.
type routingInfo struct {
	primaryMAC      string
	interfaceNumber string
	cidrs           []string
	gatewayIP       string
}

type hostScopeAllocator struct {
	allocCIDR   *net.IPNet
	allocator   *ipallocator.Range
	routingInfo *routingInfo
}

func newHostScopeAllocator(n *net.IPNet) Allocator {
	h := &hostScopeAllocator{
		allocCIDR: n,
		allocator: ipallocator.NewCIDRRange(n),
	}
	h.routingInfo = detectRoutingInfo(n)
	return h
}

func (h *hostScopeAllocator) Allocate(ip net.IP, owner string, pool Pool) (*AllocationResult, error) {
	if err := h.allocator.Allocate(ip); err != nil {
		return nil, err
	}

	result := &AllocationResult{IP: ip}
	h.applyRoutingInfo(result)
	return result, nil
}

func (h *hostScopeAllocator) AllocateWithoutSyncUpstream(ip net.IP, owner string, pool Pool) (*AllocationResult, error) {
	if err := h.allocator.Allocate(ip); err != nil {
		return nil, err
	}

	result := &AllocationResult{IP: ip}
	h.applyRoutingInfo(result)
	return result, nil
}

func (h *hostScopeAllocator) Release(ip net.IP, pool Pool) error {
	h.allocator.Release(ip)
	return nil
}

func (h *hostScopeAllocator) AllocateNext(owner string, pool Pool) (*AllocationResult, error) {
	ip, err := h.allocator.AllocateNext()
	if err != nil {
		return nil, err
	}

	result := &AllocationResult{IP: ip}
	h.applyRoutingInfo(result)
	return result, nil
}

func (h *hostScopeAllocator) AllocateNextWithoutSyncUpstream(owner string, pool Pool) (*AllocationResult, error) {
	ip, err := h.allocator.AllocateNext()
	if err != nil {
		return nil, err
	}

	result := &AllocationResult{IP: ip}
	h.applyRoutingInfo(result)
	return result, nil
}

func (h *hostScopeAllocator) Dump() (map[Pool]map[string]string, string) {
	var origIP *big.Int
	alloc := map[string]string{}
	_, data, err := h.allocator.Snapshot()
	if err != nil {
		return nil, "Unable to get a snapshot of the allocator"
	}
	if h.allocCIDR.IP.To4() != nil {
		origIP = big.NewInt(0).SetBytes(h.allocCIDR.IP.To4())
	} else {
		origIP = big.NewInt(0).SetBytes(h.allocCIDR.IP.To16())
	}
	bits := big.NewInt(0).SetBytes(data)
	for i := range bits.BitLen() {
		if bits.Bit(i) != 0 {
			ip := net.IP(big.NewInt(0).Add(origIP, big.NewInt(int64(uint(i+1)))).Bytes()).String()
			alloc[ip] = ""
		}
	}

	maxIPs := ip.CountIPsInCIDR(h.allocCIDR)
	status := fmt.Sprintf("%d/%s allocated from %s", len(alloc), maxIPs.String(), h.allocCIDR.String())

	return map[Pool]map[string]string{PoolDefault(): alloc}, status
}

func (h *hostScopeAllocator) Capacity() uint64 {
	return ip.CountIPsInCIDR(h.allocCIDR).Uint64()
}

// RestoreFinished marks the status of restoration as done
func (h *hostScopeAllocator) RestoreFinished() {}

// applyRoutingInfo stamps the cached routing information onto an AllocationResult.
func (h *hostScopeAllocator) applyRoutingInfo(result *AllocationResult) {
	if h.routingInfo == nil || result == nil {
		return
	}
	result.PrimaryMAC = h.routingInfo.primaryMAC
	result.InterfaceNumber = h.routingInfo.interfaceNumber
	result.CIDRs = h.routingInfo.cidrs
	result.GatewayIP = h.routingInfo.gatewayIP
}

// detectRoutingInfo attempts to auto-detect routing information for the
// allocation CIDR by finding a network interface that has an IP address within
// the same subnet. This enables kubernetes IPAM mode to work with multi-VNIC
// setups (e.g., Oracle Cloud, bare metal) without requiring manual configuration.
// Returns nil when no matching interface is found.
func detectRoutingInfo(allocCIDR *net.IPNet) *routingInfo {
	if allocCIDR == nil {
		return nil
	}

	links, err := safenetlink.LinkList()
	if err != nil {
		return nil
	}

	for _, link := range links {
		// Skip interfaces that are not up and operational
		if link.Attrs().OperState != netlink.OperUp &&
			link.Attrs().OperState != netlink.OperUnknown {
			continue
		}

		// Skip slave devices (we want the master device)
		if link.Attrs().RawFlags&unix.IFF_SLAVE != 0 {
			continue
		}

		// Skip loopback and other special interfaces
		if link.Attrs().Flags&net.FlagLoopback != 0 {
			continue
		}

		// Skip Cilium-managed interfaces (cilium_host, cilium_net, lxc*)
		if strings.HasPrefix(link.Attrs().Name, "cilium_") ||
			strings.HasPrefix(link.Attrs().Name, "lxc") {
			continue
		}

		// Get addresses on this interface
		family := netlink.FAMILY_V4
		if allocCIDR.IP.To4() == nil {
			family = netlink.FAMILY_V6
		}

		addrs, err := safenetlink.AddrList(link, family)
		if err != nil {
			continue
		}

		// Check if any address on this interface is within our allocation CIDR
		for _, addr := range addrs {
			// The interface's subnet should CONTAIN our allocation CIDR, not the other way around
			// This ensures we find the physical interface (e.g., enp1s0 with 100.64.0.0/18)
			// rather than virtual interfaces like cilium_host
			if addr.IPNet.Contains(allocCIDR.IP) && addr.IPNet.Contains(lastIPInCIDR(allocCIDR)) {
				return &routingInfo{
					primaryMAC:      link.Attrs().HardwareAddr.String(),
					interfaceNumber: strconv.Itoa(link.Attrs().Index),
					cidrs:           []string{addr.IPNet.String()},
					gatewayIP:       deriveGatewayFromSubnet(addr.IPNet),
				}
			}
		}
	}

	return nil
}

// lastIPInCIDR returns the last IP address in a CIDR range
func lastIPInCIDR(cidr *net.IPNet) net.IP {
	ip := make(net.IP, len(cidr.IP))
	copy(ip, cidr.IP)
	for i := range ip {
		ip[i] |= ^cidr.Mask[i]
	}
	return ip
}

// deriveGatewayFromSubnet derives the gateway IP from a subnet by using the first
// usable IP address in the subnet (typically x.x.x.1 for IPv4).
func deriveGatewayFromSubnet(subnet *net.IPNet) string {
	if subnet == nil {
		return ""
	}

	// Get the network address
	ip := subnet.IP.Mask(subnet.Mask)

	if ip.To4() != nil {
		// For IPv4, use the first address in the subnet (x.x.x.1)
		ip = ip.To4()
		ip[3] = 1
		return ip.String()
	} else {
		// For IPv6, use the first address in the subnet (ending in ::1)
		ip = ip.To16()
		ip[15] = 1
		return ip.String()
	}
}
