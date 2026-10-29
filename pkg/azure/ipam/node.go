// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/cilium/cilium/operator/pkg/ipam/nodemanager"
	"github.com/cilium/cilium/operator/pkg/ipam/stats"
	"github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/defaults"
	iputil "github.com/cilium/cilium/pkg/ip"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	cslices "github.com/cilium/cilium/pkg/slices"
)

const subnetIsFull = "SubnetIsFull"

// Node represents a node representing an Azure instance
type Node struct {
	instanceID string

	// manager is the Azure node manager responsible for this node
	manager *InstancesManager

	// node is the generic node representation
	node *nodemanager.Node

	// mutex protects members below this field
	mutex lock.RWMutex

	// k8sObj is the CiliumNode custom resource representing the node
	k8sObj *v2.CiliumNode

	// vmss is the Azure VM Scale Set the node belongs to (optional)
	vmss string
}

// UpdatedNode is called when an update to the CiliumNode is received.
func (n *Node) UpdatedNode(obj *v2.CiliumNode) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.k8sObj = obj
}

func (n *Node) requiredInterfaceName() string {
	n.mutex.RLock()
	defer n.mutex.RUnlock()
	return n.k8sObj.Spec.Azure.InterfaceName
}

// prefixDelegationAllowed reports whether the operator and the node's agent
// allow assigning prefixes to the node.
func (n *Node) prefixDelegationAllowed() bool {
	n.mutex.RLock()
	defer n.mutex.RUnlock()
	return n.node != nil && n.node.IsPrefixDelegationEnabled() &&
		n.k8sObj != nil && n.k8sObj.Spec.Azure.DisablePrefixDelegation != nil &&
		!*n.k8sObj.Spec.Azure.DisablePrefixDelegation
}

// agentUsesPrefixes reports whether the node's agent consumes prefixes.
func (n *Node) agentUsesPrefixes() bool {
	n.mutex.RLock()
	defer n.mutex.RUnlock()
	return n.k8sObj != nil && n.k8sObj.Spec.Azure.DisablePrefixDelegation != nil
}

func (n *Node) getVMSS() string {
	n.mutex.RLock()
	defer n.mutex.RUnlock()
	return n.vmss
}

func (n *Node) cacheVMSS(vmss string) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	if n.vmss == "" {
		n.vmss = vmss
	}
}

// PopulateStatusFields fills in the status field of the CiliumNode custom
// resource with Azure specific information.
//
// ForeachInterface iterates a map and Azure does not document an order for an
// interface's IP configurations, so both levels are sorted: an unchanged node
// then compares equal in ciliumNodeUpdateImplementation.UpdateStatus and the
// /status write is skipped. ID and IP are each unique within their scope, so
// sorting on them alone is deterministic.
func (n *Node) PopulateStatusFields(k8sObj *v2.CiliumNode) {
	interfaces := []types.AzureInterface{}

	n.manager.mutex.RLock()
	defer n.manager.mutex.RUnlock()
	n.manager.instances.ForeachInterface(n.instanceID, func(instanceID, interfaceID string, interfaceObj ipamTypes.Interface) error {
		iface, ok := interfaceObj.(*types.AzureInterface)
		if !ok {
			return nil
		}
		// Copied because the sorts below mutate in place and the instance
		// cache is only read locked.
		interfaces = append(interfaces, *iface.DeepCopy())
		return nil
	})

	// ID alone is a total order: it is the instance's interface map key.
	slices.SortFunc(interfaces, func(a, b types.AzureInterface) int {
		return strings.Compare(a.ID, b.ID)
	})
	for i := range interfaces {
		slices.SortFunc(interfaces[i].Addresses, func(a, b types.AzureAddress) int {
			return a.IP.Addr.Compare(b.IP.Addr)
		})
		slices.SortFunc(interfaces[i].Prefixes, func(a, b types.AzurePrefix) int {
			return a.CIDR.Addr().Compare(b.CIDR.Addr())
		})
	}
	k8sObj.Status.Azure.Interfaces = interfaces
}

// PrepareIPRelease prepares the release of IPs
func (n *Node) PrepareIPRelease(excessIPs int, scopedLog *slog.Logger) *nodemanager.ReleaseAction {
	return &nodemanager.ReleaseAction{}
}

// ReleaseIPPrefixes is a no-op on Azure since Azure ENIs don't
// support prefix delegation.
func (n *Node) ReleaseIPPrefixes(ctx context.Context, r *nodemanager.ReleaseAction) error {
	// nothing to do
	return nil
}

// ReleaseIPs performs the IP release operation
func (n *Node) ReleaseIPs(ctx context.Context, r *nodemanager.ReleaseAction) error {
	return fmt.Errorf("not implemented")
}

// PrepareIPAllocation returns the number of IPs that can be allocated/created.
func (n *Node) PrepareIPAllocation(scopedLog *slog.Logger) (a *nodemanager.AllocationAction, err error) {
	a = &nodemanager.AllocationAction{}
	requiredIfaceName := n.requiredInterfaceName()
	n.manager.mutex.RLock()
	defer n.manager.mutex.RUnlock()
	usePrimary := n.manager.usePrimary
	perSlot := n.addressesPerSlotLocked()
	err = n.manager.instances.ForeachInterface(n.instanceID, func(instanceID, interfaceID string, interfaceObj ipamTypes.Interface) error {
		iface, ok := interfaceObj.(*types.AzureInterface)
		if !ok {
			return fmt.Errorf("invalid interface object")
		}

		availableOnInterface, available := isAvailableInterface(requiredIfaceName, iface, usePrimary, perSlot, scopedLog)
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

			var preferredPoolIDs []ipamTypes.PoolID
			if iface.Subnet.ID != "" {
				preferredPoolIDs = []ipamTypes.PoolID{ipamTypes.PoolID(iface.Subnet.ID)}
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

// AllocateIPs performs the Azure IP allocation operation. With prefix
// delegation it assigns prefixes, and falls back to individual addresses if the
// subnet has no prefix left.
func (n *Node) AllocateIPs(ctx context.Context, a *nodemanager.AllocationAction) error {
	iface, ok := a.Interface.(*types.AzureInterface)
	if !ok {
		return fmt.Errorf("invalid interface object")
	}

	prefixDelegated, free, err := n.allocationMode(a.InterfaceID)
	if err != nil {
		return err
	}

	if prefixDelegated {
		prefixes := min(iputil.PrefixCeil(a.IPv4.AvailableForAllocation, types.PrefixSizeIPv4), free)
		err := n.assign(ctx, iface, a.PoolID, prefixes, types.PrefixLengthIPv4)
		if err == nil {
			a.IPv4.AvailableForAllocation = prefixes * types.PrefixSizeIPv4
			return nil
		}
		if !isSubnetOutOfPrefixes(err) {
			return err
		}
		n.manager.logger.Warn("Subnet might be out of prefixes, allocating individual IPs instead",
			logfields.InstanceID, n.instanceID,
			logfields.Error, err,
		)
	}

	assigned, err := n.assignAddressesHalvingOnSubnetFull(ctx, iface, a.PoolID, min(a.IPv4.AvailableForAllocation, free))
	if err != nil {
		return err
	}
	a.IPv4.AvailableForAllocation = assigned
	return nil
}

// allocationMode returns whether prefixes are assigned to the node and the
// free IP configuration slots on its interface with the given ID.
func (n *Node) allocationMode(interfaceID string) (prefixDelegated bool, free int, err error) {
	n.manager.mutex.RLock()
	defer n.manager.mutex.RUnlock()

	found := false
	n.manager.instances.ForeachInterface(n.instanceID, func(_, id string, interfaceObj ipamTypes.Interface) error {
		iface, ok := interfaceObj.(*types.AzureInterface)
		if ok && id == interfaceID {
			found = true
			free = freeSlots(iface, n.manager.usePrimary)
		}
		return nil
	})
	if !found {
		return false, 0, fmt.Errorf("interface %s not found on instance %s", interfaceID, n.instanceID)
	}
	return n.isPrefixDelegatedLocked(), free, nil
}

func (n *Node) assign(ctx context.Context, iface *types.AzureInterface, poolID ipamTypes.PoolID, count int, prefixLength int32) error {
	vmss := iface.GetVMScaleSetName()
	if vmss == "" {
		return n.manager.api.AssignPrivateIpAddressesVM(ctx, string(poolID), iface.Name, count, prefixLength)
	}
	return n.manager.api.AssignPrivateIpAddressesVMSS(ctx, iface.GetVMID(), vmss, string(poolID), iface.Name, count, prefixLength)
}

// assignAddressesHalvingOnSubnetFull assigns count individual addresses,
// retrying with half as many while the subnet is too full, and returns how
// many were assigned.
func (n *Node) assignAddressesHalvingOnSubnetFull(ctx context.Context, iface *types.AzureInterface, poolID ipamTypes.PoolID, count int) (int, error) {
	for {
		err := n.assign(ctx, iface, poolID, count, 0)
		if err == nil {
			return count, nil
		}
		if count <= 1 || !isSubnetFull(err) {
			return 0, err
		}
		count /= 2
	}
}

func isSubnetFull(err error) bool {
	respErr, ok := errors.AsType[*azcore.ResponseError](err)
	return ok && respErr.ErrorCode == subnetIsFull
}

// isSubnetOutOfPrefixes reports whether a prefix request failed because the
// subnet has no free aligned prefix. Azure returns the same error code when it
// has too few addresses, so this only holds for prefix requests.
func isSubnetOutOfPrefixes(err error) bool {
	return isSubnetFull(err)
}

func (n *Node) AllocateStaticIP(ctx context.Context, staticIPTags ipamTypes.Tags) (netip.Addr, error) {
	var addr netip.Addr
	var err error
	if vmss := n.getVMSS(); vmss == "" {
		addr, err = n.manager.api.AssignPublicIPAddressesVM(ctx, n.instanceID, staticIPTags)
	} else {
		addr, err = n.manager.api.AssignPublicIPAddressesVMSS(ctx, n.instanceID, vmss, staticIPTags)
	}
	if err != nil {
		return netip.Addr{}, err
	}
	return addr, nil
}

// CreateInterface is called to create a new interface. This operation is
// currently not supported on Azure.
func (n *Node) CreateInterface(ctx context.Context, allocation *nodemanager.AllocationAction, scopedLog *slog.Logger) (int, string, error) {
	return 0, "", fmt.Errorf("not implemented")
}

// ResyncInterfacesAndIPs is called to retrieve interfaces and IPs known
// to the Azure API and return them
func (n *Node) ResyncInterfacesAndIPs(ctx context.Context, scopedLog *slog.Logger) (
	available ipamTypes.AllocationMap,
	stats stats.InterfaceStats,
	err error) {

	if n.instanceID == "" {
		return nil, stats, nil
	}

	available = ipamTypes.AllocationMap{}
	n.manager.mutex.RLock()
	defer n.manager.mutex.RUnlock()
	usePrimary := n.manager.usePrimary

	requiredIfaceName := n.requiredInterfaceName()
	err = n.manager.instances.ForeachInterface(n.instanceID, func(instanceID, interfaceID string, interfaceObj ipamTypes.Interface) error {
		iface, ok := interfaceObj.(*types.AzureInterface)
		if !ok {
			return fmt.Errorf("invalid interface object")
		}

		for _, address := range iface.Addresses {
			if address.State == types.StateSucceeded {
				available[address.IP] = ipamTypes.AllocationIP{Resource: interfaceID}
			} else {
				scopedLog.Warn(
					"Ignoring potentially available IP due to non-successful state",
					logfields.IPAddr, address.IP,
					logfields.State, address.State,
				)
			}
		}

		// Cache the VMSS name from the first interface we see
		n.cacheVMSS(iface.GetVMScaleSetName())

		if _, isAvailable := isAvailableInterface(requiredIfaceName, iface, usePrimary, 1, scopedLog); isAvailable {
			stats.RemainingAvailableInterfaceCount++
		}
		return nil
	})
	if err != nil {
		return nil, stats, err
	}
	stats.NodeIPv4PrefixedAddresses, stats.NodeCapacity = n.capacityLocked(requiredIfaceName, usePrimary)

	return available, stats, nil
}

// capacityLocked returns the number of addresses in usable prefixes and the
// node capacity: the usable attached addresses plus the free slots on the
// interfaces allocation may use. n.manager.mutex must be held.
func (n *Node) capacityLocked(requiredIfaceName string, usePrimary bool) (prefixedAddresses, capacity int) {
	usesPrefixes := n.agentUsesPrefixes()
	perSlot := n.addressesPerSlotLocked()
	n.manager.instances.ForeachInterface(n.instanceID, func(_, _ string, interfaceObj ipamTypes.Interface) error {
		iface, ok := interfaceObj.(*types.AzureInterface)
		if !ok {
			return nil
		}
		for _, address := range iface.Addresses {
			if address.State == types.StateSucceeded {
				capacity++
			}
		}
		if usesPrefixes {
			prefixedAddresses += len(iface.UsablePrefixes()) * types.PrefixSizeIPv4
		}
		if matchesInterfaceName(requiredIfaceName, iface) {
			capacity += freeSlots(iface, usePrimary) * perSlot
		}
		return nil
	})
	return prefixedAddresses, capacity + prefixedAddresses
}

// GetMaximumAllocatableIPv4 returns the maximum amount of IPv4 addresses
// that can be allocated to the instance
func (n *Node) GetMaximumAllocatableIPv4() int {
	if n == nil || n.manager == nil {
		return types.InterfaceAddressLimit
	}

	requiredIfaceName := n.requiredInterfaceName()
	n.manager.mutex.RLock()
	defer n.manager.mutex.RUnlock()
	_, capacity := n.capacityLocked(requiredIfaceName, n.manager.usePrimary)
	return capacity
}

// GetMinimumAllocatableIPv4 returns the minimum amount of IPv4 addresses that
// must be allocated to the instance.
func (n *Node) GetMinimumAllocatableIPv4() int {
	return defaults.IPAMPreAllocation
}

// IsPrefixDelegated reports whether prefixes are assigned to the node.
func (n *Node) IsPrefixDelegated() bool {
	if n == nil || n.manager == nil {
		return false
	}
	n.manager.mutex.RLock()
	defer n.manager.mutex.RUnlock()
	return n.isPrefixDelegatedLocked()
}

// isPrefixDelegatedLocked reports whether prefixes are assigned to the node:
// prefix delegation must be allowed, and like on AWS, no interface may have
// secondary addresses without also having prefixes. n.manager.mutex must be
// held.
func (n *Node) isPrefixDelegatedLocked() bool {
	if !n.prefixDelegationAllowed() {
		return false
	}
	mixed := false
	n.manager.instances.ForeachInterface(n.instanceID, func(_, _ string, interfaceObj ipamTypes.Interface) error {
		iface, ok := interfaceObj.(*types.AzureInterface)
		if !ok || len(iface.Prefixes) > 0 {
			return nil
		}
		if slices.ContainsFunc(iface.Addresses, func(address types.AzureAddress) bool {
			return address.IP.Addr != iface.IP.Addr
		}) {
			mixed = true
		}
		return nil
	})
	return !mixed
}

// addressesPerSlotLocked returns the number of addresses a free IP
// configuration slot provides. n.manager.mutex must be held.
func (n *Node) addressesPerSlotLocked() int {
	if n.isPrefixDelegatedLocked() {
		return types.PrefixSizeIPv4
	}
	return 1
}

func secondaryIPv4CIDR(iface *types.AzureInterface, address types.AzureAddress) (netip.Prefix, bool) {
	if !address.IP.IsValid() || !address.IP.Addr.Is4() || address.IP.Addr == iface.IP.Addr {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(address.IP.Addr, address.IP.Addr.BitLen()), true
}

func (n *Node) GetAttachedCIDRs() []netip.Prefix {
	if n.instanceID == "" {
		return nil
	}

	n.manager.mutex.RLock()
	defer n.manager.mutex.RUnlock()

	var attached []netip.Prefix
	n.manager.instances.ForeachInterface(n.instanceID, func(_, _ string, interfaceObj ipamTypes.Interface) error {
		iface, ok := interfaceObj.(*types.AzureInterface)
		if !ok {
			return nil
		}
		for _, address := range iface.Addresses {
			if address.IP.IsValid() && address.IP.Addr.Is4() {
				attached = append(attached, netip.PrefixFrom(address.IP.Addr, address.IP.Addr.BitLen()))
			}
		}
		for _, prefix := range iface.Prefixes {
			if prefix.CIDR.IsValid() && prefix.CIDR.Addr().Is4() {
				attached = append(attached, prefix.CIDR.Prefix)
			}
		}
		return nil
	})
	return attached
}

func (n *Node) PrepareCIDRRelease(released []netip.Prefix) []*nodemanager.ReleaseAction {
	if n.instanceID == "" {
		return nil
	}

	n.manager.mutex.RLock()
	defer n.manager.mutex.RUnlock()

	requiredIfaceName := n.requiredInterfaceName()
	var actions []*nodemanager.ReleaseAction
	n.manager.instances.ForeachInterface(n.instanceID, func(_, interfaceID string, interfaceObj ipamTypes.Interface) error {
		iface, ok := interfaceObj.(*types.AzureInterface)
		if !ok || !matchesInterfaceName(requiredIfaceName, iface) {
			return nil
		}
		var cidrs []netip.Prefix
		for _, address := range iface.Addresses {
			if address.State != types.StateSucceeded {
				continue
			}
			if prefix, ok := secondaryIPv4CIDR(iface, address); ok && slices.Contains(released, prefix) {
				cidrs = append(cidrs, prefix)
			}
		}
		if len(cidrs) > 0 {
			actions = append(actions, &nodemanager.ReleaseAction{
				InterfaceID:    interfaceID,
				PoolID:         ipamTypes.PoolID(iface.Subnet.ID),
				CIDRsToRelease: cidrs,
			})
		}
		return nil
	})
	return actions
}

func (n *Node) ReleaseCIDRs(ctx context.Context, r *nodemanager.ReleaseAction) ([]netip.Prefix, error) {
	n.manager.mutex.RLock()
	interfaceObj, ok := n.manager.instances.GetInterface(n.instanceID, r.InterfaceID)
	n.manager.mutex.RUnlock()
	if !ok {
		return nil, fmt.Errorf("interface %s not found on instance %s", r.InterfaceID, n.instanceID)
	}
	iface, ok := interfaceObj.(*types.AzureInterface)
	if !ok {
		return nil, fmt.Errorf("invalid interface object")
	}

	addrs := cslices.Map(r.CIDRsToRelease, netip.Prefix.Addr)

	var err error
	vmss := iface.GetVMScaleSetName()
	if vmss == "" {
		err = n.manager.api.UnassignPrivateIpAddressesVM(ctx, iface.Name, addrs)
	} else {
		err = n.manager.api.UnassignPrivateIpAddressesVMSS(ctx, iface.GetVMID(), vmss, iface.Name, addrs)
	}
	if err != nil {
		return nil, err
	}

	n.manager.removeIPsFromInterface(n.instanceID, r.InterfaceID, addrs)
	return r.CIDRsToRelease, nil
}

func matchesInterfaceName(requiredIfaceName string, iface *types.AzureInterface) bool {
	return requiredIfaceName == "" || iface.Name == requiredIfaceName
}

// isAvailableInterface returns whether interface is available and the number of available IPs to allocate in interface
func isAvailableInterface(requiredIfaceName string, iface *types.AzureInterface, usePrimary bool, perSlot int, scopedLog *slog.Logger) (availableOnInterface int, available bool) {
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

	availableOnInterface = freeSlots(iface, usePrimary) * perSlot
	if availableOnInterface <= 0 {
		return 0, false
	}
	return availableOnInterface, true
}

// slotUsage counts the IP configuration slots used on the NIC: the primary
// (whether or not it is exposed), secondary addresses and prefixes.
func slotUsage(iface *types.AzureInterface, usePrimary bool) int {
	used := len(iface.Addresses) + len(iface.Prefixes)
	// An exposed primary is already in iface.Addresses.
	if !usePrimary && iface.IP.IsValid() {
		used++
	}
	return used
}

// freeSlots returns the IP configuration slots still free on the NIC.
func freeSlots(iface *types.AzureInterface, usePrimary bool) int {
	return max(types.InterfaceAddressLimit-slotUsage(iface, usePrimary), 0)
}
