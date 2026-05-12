// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"

	"github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/defaults"
	pkgip "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/ipam/stats"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type ipamNodeActions interface {
	InstanceID() string
	IsPrefixDelegationEnabled() bool
}

// Node represents a node representing an Azure instance
type Node struct {
	// k8sObj is the CiliumNode custom resource representing the node
	k8sObj *v2.CiliumNode

	// node contains the general purpose fields of a node
	node ipamNodeActions

	// manager is the Azure node manager responsible for this node
	manager *InstancesManager

	// vmss is the Azure VM Scale Set the node belongs to (optional)
	vmss string
}

// UpdatedNode is called when an update to the CiliumNode is received.
func (n *Node) UpdatedNode(obj *v2.CiliumNode) {
	n.k8sObj = obj
}

// PopulateStatusFields fills in the status field of the CiliumNode custom
// resource with Azure specific information
func (n *Node) PopulateStatusFields(k8sObj *v2.CiliumNode) {
	k8sObj.Status.Azure.Interfaces = []types.AzureInterface{}

	n.manager.mutex.RLock()
	defer n.manager.mutex.RUnlock()
	n.manager.instances.ForeachInterface(n.node.InstanceID(), func(instanceID, interfaceID string, interfaceObj ipamTypes.InterfaceRevision) error {
		iface, ok := interfaceObj.Resource.(*types.AzureInterface)
		if ok {
			k8sObj.Status.Azure.Interfaces = append(k8sObj.Status.Azure.Interfaces, *(iface.DeepCopy()))
		}
		return nil
	})
}

// PrepareIPRelease selects up to excessIPs worth of fully-unused Prefix on NIC
// prefixes for release. Releasing partial prefixes is not supported; a prefix
// is eligible only when none of its 16 IPs appear in Status.IPAM.Used. Mirrors
// the prefix-release branch of pkg/aws/eni/node.go's PrepareIPRelease.
//
// AWS additionally filters secondary IPs that don't belong to any prefix via
// getIndividualIPs/getUnusedIPs and adds them to IPsToRelease. Azure does not
// port those helpers here because ReleaseIPs is currently `not implemented`,
// so per-IP release is not in scope. The mixed-mode guard in IsPrefixDelegated
// ensures any Addresses on a prefix-delegated NIC came from a prefix
// expansion, so the matched-IPs collection below is exhaustive for the
// release flow we support today.
func (n *Node) PrepareIPRelease(excessIPs int, scopedLog *slog.Logger) *ipam.ReleaseAction {
	r := &ipam.ReleaseAction{}
	if excessIPs < ipamOption.ENIPDBlockSizeIPv4 {
		return r
	}

	n.manager.mutex.RLock()
	defer n.manager.mutex.RUnlock()

	usedIPs := n.k8sObj.Status.IPAM.Used

	var ifaces []*types.AzureInterface
	_ = n.manager.instances.ForeachInterface(n.node.InstanceID(), func(instanceID, interfaceID string, interfaceObj ipamTypes.InterfaceRevision) error {
		if iface, ok := interfaceObj.Resource.(*types.AzureInterface); ok {
			ifaces = append(ifaces, iface)
		}
		return nil
	})
	sort.Slice(ifaces, func(i, j int) bool { return ifaces[i].ID < ifaces[j].ID })

	remaining := excessIPs
	for _, iface := range ifaces {
		if len(iface.Prefixes) == 0 || remaining < ipamOption.ENIPDBlockSizeIPv4 {
			continue
		}
		var unusedPrefixes, matchedIPs []string
		for _, prefix := range iface.Prefixes {
			if remaining < ipamOption.ENIPDBlockSizeIPv4 {
				break
			}
			pfx, err := netip.ParsePrefix(prefix)
			if err != nil {
				continue
			}
			if prefixHasUsedIP(pfx, usedIPs) {
				continue
			}
			unusedPrefixes = append(unusedPrefixes, prefix)
			for _, addr := range iface.Addresses {
				ip, err := netip.ParseAddr(addr.IP)
				if err != nil {
					continue
				}
				if pfx.Contains(ip) {
					matchedIPs = append(matchedIPs, addr.IP)
				}
			}
			remaining -= ipamOption.ENIPDBlockSizeIPv4
		}
		if len(unusedPrefixes) == 0 {
			continue
		}
		r.InterfaceID = iface.ID
		for _, addr := range iface.Addresses {
			if addr.Subnet != "" {
				r.PoolID = ipamTypes.PoolID(addr.Subnet)
				break
			}
		}
		r.IPPrefixesToRelease = unusedPrefixes
		r.IPsToRelease = matchedIPs
		scopedLog.Debug(
			"Interface has unused Prefix on NIC prefixes to release",
			logfields.ID, iface.ID,
			logfields.Prefix, unusedPrefixes,
			logfields.IPAddrs, matchedIPs,
		)
		return r
	}
	return r
}

// prefixHasUsedIP reports whether any used IP falls within the given prefix.
func prefixHasUsedIP(pfx netip.Prefix, used ipamTypes.AllocationMap) bool {
	for ipStr := range used {
		ip, err := netip.ParseAddr(ipStr)
		if err != nil {
			continue
		}
		if pfx.Contains(ip) {
			return true
		}
	}
	return false
}

// ReleaseIPPrefixes releases Prefix on NIC prefixes from the target interface.
// Selects VM vs VMSS write path based on the cached interface's VMSS metadata.
// Interface fields are snapshotted under the manager lock to avoid racing a
// concurrent resync mutating the cached AzureInterface pointer.
func (n *Node) ReleaseIPPrefixes(ctx context.Context, r *ipam.ReleaseAction) error {
	if len(r.IPPrefixesToRelease) == 0 {
		return nil
	}

	var (
		ifaceName, vmssName, vmID string
		found                     bool
	)
	n.manager.mutex.RLock()
	_ = n.manager.instances.ForeachInterface(n.node.InstanceID(), func(instanceID, interfaceID string, interfaceObj ipamTypes.InterfaceRevision) error {
		iface, ok := interfaceObj.Resource.(*types.AzureInterface)
		if !ok || iface.ID != r.InterfaceID {
			return nil
		}
		ifaceName = iface.Name
		vmssName = iface.GetVMScaleSetName()
		vmID = iface.GetVMID()
		found = true
		return nil
	})
	n.manager.mutex.RUnlock()
	if !found {
		return fmt.Errorf("interface %s not found on instance %s", r.InterfaceID, n.node.InstanceID())
	}

	if vmssName == "" {
		return n.manager.api.UnassignPrivatePrefixesVM(ctx, ifaceName, r.IPPrefixesToRelease)
	}
	return n.manager.api.UnassignPrivatePrefixesVMSS(ctx, vmID, vmssName, ifaceName, r.IPPrefixesToRelease)
}

// ReleaseIPs performs the IP release operation. Per-IP release is not
// implemented for Azure (mirrors AWS's prefix-only release flow for v1.19);
// when the IPAM framework chains ReleaseIPs after a successful
// ReleaseIPPrefixes on the same ReleaseAction, all IPs in r.IPsToRelease are
// prefix-expanded and were already unassigned by the Unassign*Prefixes call.
// Returning nil in that case lets the framework complete the release
// handshake.
func (n *Node) ReleaseIPs(ctx context.Context, r *ipam.ReleaseAction) error {
	if len(r.IPPrefixesToRelease) > 0 {
		return nil
	}
	return fmt.Errorf("not implemented")
}

// PrepareIPAllocation returns the number of IPs that can be allocated/created.
func (n *Node) PrepareIPAllocation(scopedLog *slog.Logger) (a *ipam.AllocationAction, err error) {
	a = &ipam.AllocationAction{}
	requiredIfaceName := n.k8sObj.Spec.Azure.InterfaceName
	n.manager.mutex.RLock()
	defer n.manager.mutex.RUnlock()
	prefixDelegated := n.isPrefixDelegatedLocked()
	err = n.manager.instances.ForeachInterface(n.node.InstanceID(), func(instanceID, interfaceID string, interfaceObj ipamTypes.InterfaceRevision) error {
		iface, ok := interfaceObj.Resource.(*types.AzureInterface)
		if !ok {
			return fmt.Errorf("invalid interface object")
		}

		availableOnInterface, available := isAvailableInterface(requiredIfaceName, iface, prefixDelegated, scopedLog)
		if !available {
			return nil
		}

		a.IPv4.InterfaceCandidates++

		if a.InterfaceID == "" {
			scopedLog.Debug(
				"Interface has IPs available",
				logfields.ID, iface.ID,
				logfields.AvailableAddresses, availableOnInterface,
			)

			preferredPoolIDs := []ipamTypes.PoolID{}
			for _, address := range iface.Addresses {
				if address.Subnet != "" {
					preferredPoolIDs = append(preferredPoolIDs, ipamTypes.PoolID(address.Subnet))
				}
			}

			poolID, available := n.manager.subnets.FirstSubnetWithAvailableAddresses(preferredPoolIDs)
			if poolID != ipamTypes.PoolNotExists {
				scopedLog.Debug(
					"Subnet has IPs available",
					logfields.SubnetID, poolID,
					logfields.AvailableAddresses, available,
				)

				a.InterfaceID = iface.ID
				a.Interface = interfaceObj
				a.PoolID = poolID
				a.IPv4.AvailableForAllocation = min(available, availableOnInterface)
			}
		}
		return nil
	})

	return
}

// AllocateIPs performs the Azure IP allocation operation. When Prefix on NIC
// is enabled and the target interface qualifies, the operator first attempts
// to allocate /28 prefixes. On subnet prefix-capacity exhaustion (Azure
// reports the subnet has no free /28 block) the operator falls through to
// individual IP allocation on the same NIC, mirroring AWS Prefix Delegation
// (pkg/aws/eni/node.go AllocateIPs).
func (n *Node) AllocateIPs(ctx context.Context, a *ipam.AllocationAction) error {
	iface, ok := a.Interface.Resource.(*types.AzureInterface)
	if !ok {
		return fmt.Errorf("invalid interface object")
	}

	if n.IsPrefixDelegated() {
		numPrefixes := pkgip.PrefixCeil(a.IPv4.AvailableForAllocation, ipamOption.ENIPDBlockSizeIPv4)
		var err error
		if iface.GetVMScaleSetName() == "" {
			err = n.manager.api.AssignPrivatePrefixesVM(ctx, string(a.PoolID), iface.Name, numPrefixes)
		} else {
			err = n.manager.api.AssignPrivatePrefixesVMSS(ctx, iface.GetVMID(), iface.GetVMScaleSetName(), string(a.PoolID), iface.Name, numPrefixes)
		}
		if !isSubnetAtPrefixCapacity(err) {
			return err
		}
		n.manager.logger.Warn(
			"Azure subnet appears out of /28 prefixes; falling back to individual IP allocation on this NIC",
			logfields.Node, n.k8sObj.Name,
			logfields.Interface, iface.Name,
			logfields.Error, err,
		)
	}

	// On fallback, cap to the per-NIC IP-configuration limit. AvailableForAllocation
	// was computed against the prefix-mode limit (16x larger), so without this cap
	// we would request more secondaries than Azure permits on a single NIC.
	toAllocate := min(a.IPv4.AvailableForAllocation, max(types.InterfaceAddressLimit-len(iface.Addresses), 0))
	if toAllocate <= 0 {
		return nil
	}

	if iface.GetVMScaleSetName() == "" {
		return n.manager.api.AssignPrivateIpAddressesVM(ctx, string(a.PoolID), iface.Name, toAllocate)
	}
	return n.manager.api.AssignPrivateIpAddressesVMSS(ctx, iface.GetVMID(), iface.GetVMScaleSetName(), string(a.PoolID), iface.Name, toAllocate)
}

// isSubnetAtPrefixCapacity reports whether err looks like an Azure "subnet has
// no free /28 prefix" failure. The raw error is logged at Warn by the Assign
// methods in pkg/azure/api so the actual code/message is recoverable from
// operator logs if Azure introduces a new variant.
func isSubnetAtPrefixCapacity(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "NoAvailableIPAddressesInSubnet") ||
		strings.Contains(msg, "SubnetIsFull") ||
		strings.Contains(msg, "PrefixUnavailable") ||
		strings.Contains(msg, "InsufficientCidrBlocks")
}

func (n *Node) AllocateStaticIP(ctx context.Context, staticIPTags ipamTypes.Tags) (string, error) {
	if n.vmss == "" {
		return n.manager.api.AssignPublicIPAddressesVM(ctx, n.node.InstanceID(), staticIPTags)
	}
	return n.manager.api.AssignPublicIPAddressesVMSS(ctx, n.node.InstanceID(), n.vmss, staticIPTags)
}

// CreateInterface is called to create a new interface. This operation is
// currently not supported on Azure.
func (n *Node) CreateInterface(ctx context.Context, allocation *ipam.AllocationAction, scopedLog *slog.Logger) (int, string, error) {
	return 0, "", fmt.Errorf("not implemented")
}

// ResyncInterfacesAndIPs is called to retrieve interfaces and IPs known
// to the Azure API and return them
func (n *Node) ResyncInterfacesAndIPs(ctx context.Context, scopedLog *slog.Logger) (
	available ipamTypes.AllocationMap,
	stats stats.InterfaceStats,
	err error) {

	// Azure virtual machines always have an upper limit of 256 addresses.
	// Both VMs and NICs can have a maximum of 256 addresses, so as long as
	// there is at least one available NIC, we can allocate up to 256 addresses
	// on the VM (minus the primary IP address).
	stats.NodeCapacity = max(n.GetMaximumAllocatableIPv4()-1, 0)

	if n.node.InstanceID() == "" {
		return nil, stats, nil
	}

	available = ipamTypes.AllocationMap{}
	n.manager.mutex.RLock()
	defer n.manager.mutex.RUnlock()
	prefixDelegated := n.isPrefixDelegatedLocked()
	err = n.manager.instances.ForeachAddress(n.node.InstanceID(), func(instanceID, interfaceID, ip, poolID string, addressObj ipamTypes.Address) error {
		address, ok := addressObj.(types.AzureAddress)
		if !ok {
			scopedLog.Warn(
				"Not an Azure address object, ignoring IP",
				logfields.IPAddr, ip,
			)
			return nil
		}

		if address.State == types.StateSucceeded {
			available[address.IP] = ipamTypes.AllocationIP{Resource: interfaceID}
		} else {
			scopedLog.Warn(
				"Ignoring potentially available IP due to non-successful state",
				logfields.IPAddr, ip,
				logfields.State, address.State,
			)
		}
		return nil
	})
	if err != nil {
		return nil, stats, err
	}

	requiredIfaceName := n.k8sObj.Spec.Azure.InterfaceName
	err = n.manager.instances.ForeachInterface(n.node.InstanceID(), func(instanceID, interfaceID string, interfaceObj ipamTypes.InterfaceRevision) error {
		iface, ok := interfaceObj.Resource.(*types.AzureInterface)
		if !ok {
			return fmt.Errorf("invalid interface object")
		}

		// Cache the VMSS name from the first interface we see
		if n.vmss == "" {
			n.vmss = iface.GetVMScaleSetName()
		}

		_, available := isAvailableInterface(requiredIfaceName, iface, prefixDelegated, scopedLog)
		if available {
			stats.RemainingAvailableInterfaceCount++
		}
		return nil
	})
	if err != nil {
		return nil, stats, err
	}

	return available, stats, nil
}

// GetMaximumAllocatableIPv4 returns the maximum amount of IPv4 addresses
// that can be allocated to the instance
func (n *Node) GetMaximumAllocatableIPv4() int {
	// An Azure node can allocate up to 256 private IP addresses
	// source: https://github.com/MicrosoftDocs/azure-docs/blob/master/includes/azure-virtual-network-limits.md#networking-limits---azure-resource-manager
	return types.InterfaceAddressLimit
}

// GetMinimumAllocatableIPv4 returns the minimum amount of IPv4 addresses that
// must be allocated to the instance.
func (n *Node) GetMinimumAllocatableIPv4() int {
	return defaults.IPAMPreAllocation
}

// IsPrefixDelegated reports whether Azure Prefix on NIC should be used for new
// allocations on this node. Returns false if the operator-wide flag is off or
// if the per-node CRD opts out. Unlike AWS, Azure does not require an
// all-or-nothing posture per NIC, so there is no mixed-mode guard here.
//
// Callers already holding n.manager.mutex must use isPrefixDelegatedLocked
// instead; the manager's read-write mutex is not reentrant and a nested RLock
// can deadlock under writer contention.
func (n *Node) IsPrefixDelegated() bool {
	n.manager.mutex.RLock()
	defer n.manager.mutex.RUnlock()
	return n.isPrefixDelegatedLocked()
}

// isPrefixDelegatedLocked is the lock-free body of IsPrefixDelegated. Callers
// must hold n.manager.mutex (read or write).
//
// Azure permits mixing single-IP secondary configurations and /28 Prefix on
// NIC configurations on the same NIC at the REST layer (each secondary IP
// config independently chooses between a single IP and a CIDR block per
// learn.microsoft.com/.../private-ip-addresses), so no mixed-mode guard is
// imposed here.
func (n *Node) isPrefixDelegatedLocked() bool {
	if n.node == nil || !n.node.IsPrefixDelegationEnabled() {
		return false
	}
	if n.k8sObj.Spec.Azure.DisablePrefixDelegation != nil && *n.k8sObj.Spec.Azure.DisablePrefixDelegation {
		return false
	}
	return true
}

// isAvailableInterface returns whether interface is available and the number
// of IPs that can still be allocated on it. When prefixDelegated is true the
// per-interface capacity is expressed in IPs of /28 worth (16 each), so the
// effective limit is InterfaceAddressLimit * ENIPDBlockSizeIPv4. When false
// but Prefixes is non-empty (a node where prefix delegation was previously on
// then disabled), the leftover prefix capacity is added back so existing
// prefix-derived IPs remain usable.
func isAvailableInterface(requiredIfaceName string, iface *types.AzureInterface, prefixDelegated bool, scopedLog *slog.Logger) (availableOnInterface int, available bool) {
	if requiredIfaceName != "" {
		if iface.Name != requiredIfaceName {
			scopedLog.Debug(
				"Not considering interface as available since it does not match the required name",
				logfields.Interface, iface.Name,
				logfields.Required, requiredIfaceName,
			)
			return 0, false
		}
	}

	scopedLog.Debug(
		"Considering interface as available",
		logfields.ID, iface.ID,
		logfields.NumAddresses, len(iface.Addresses),
	)

	limit := types.InterfaceAddressLimit
	if prefixDelegated {
		limit *= ipamOption.ENIPDBlockSizeIPv4
	} else if len(iface.Prefixes) > 0 {
		// Mirror pkg/aws/eni/node.go getEffectiveIPLimits: each leftover prefix
		// occupies one IP-configuration slot but yields 16 IPs, so add back
		// the extra 15 per prefix.
		limit += len(iface.Prefixes) * (ipamOption.ENIPDBlockSizeIPv4 - 1)
	}

	availableOnInterface = max(limit-len(iface.Addresses), 0)
	if availableOnInterface <= 0 {
		return 0, false
	}
	return availableOnInterface, true
}
