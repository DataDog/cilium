// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"fmt"
	"math/big"
	"net"
	"strconv"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam/service/ipallocator"
)

type hostScopeAllocator struct {
	allocCIDR *net.IPNet
	allocator *ipallocator.Range
}

func newHostScopeAllocator(n *net.IPNet) Allocator {
	return &hostScopeAllocator{
		allocCIDR: n,
		allocator: ipallocator.NewCIDRRange(n),
	}
}

func (h *hostScopeAllocator) Allocate(ip net.IP, owner string, pool Pool) (*AllocationResult, error) {
	if err := h.allocator.Allocate(ip); err != nil {
		return nil, err
	}

	result := &AllocationResult{IP: ip}
	h.populateRoutingInfo(result)
	return result, nil
}

func (h *hostScopeAllocator) AllocateWithoutSyncUpstream(ip net.IP, owner string, pool Pool) (*AllocationResult, error) {
	if err := h.allocator.Allocate(ip); err != nil {
		return nil, err
	}

	result := &AllocationResult{IP: ip}
	h.populateRoutingInfo(result)
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
	h.populateRoutingInfo(result)
	return result, nil
}

func (h *hostScopeAllocator) AllocateNextWithoutSyncUpstream(owner string, pool Pool) (*AllocationResult, error) {
	ip, err := h.allocator.AllocateNext()
	if err != nil {
		return nil, err
	}

	result := &AllocationResult{IP: ip}
	h.populateRoutingInfo(result)
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

// populateRoutingInfo attempts to auto-detect routing information for the
// allocation CIDR by finding a network interface that has an IP address within
// the same subnet. This enables kubernetes IPAM mode to work with multi-VNIC
// setups (e.g., Oracle Cloud, bare metal) without requiring manual configuration.
func (h *hostScopeAllocator) populateRoutingInfo(result *AllocationResult) {
	if result == nil || h.allocCIDR == nil {
		return
	}

	// Try to detect routing info from network interfaces
	links, err := safenetlink.LinkList()
	if err != nil {
		return
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

		// Get addresses on this interface
		family := netlink.FAMILY_V4
		if h.allocCIDR.IP.To4() == nil {
			family = netlink.FAMILY_V6
		}

		addrs, err := safenetlink.AddrList(link, family)
		if err != nil {
			continue
		}

		// Check if any address on this interface is within our allocation CIDR
		for _, addr := range addrs {
			if h.allocCIDR.Contains(addr.IP) {
				// Found the interface that owns this CIDR!
				result.PrimaryMAC = link.Attrs().HardwareAddr.String()
				result.InterfaceNumber = strconv.Itoa(link.Attrs().Index)
				result.CIDRs = []string{addr.IPNet.String()}
				result.GatewayIP = deriveGatewayFromSubnet(addr.IPNet)
				return
			}
		}
	}
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
