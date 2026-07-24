// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"

	"github.com/cilium/cilium/operator/pkg/ipam/nodemanager"
	"github.com/cilium/cilium/operator/pkg/ipam/stats"
	"github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/defaults"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type ipamNodeActions interface {
	InstanceID() string
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
	n.manager.instances.ForeachInterface(n.node.InstanceID(), func(instanceID, interfaceID string, interfaceObj ipamTypes.Interface) error {
		iface, ok := interfaceObj.(*types.AzureInterface)
		if ok {
			k8sObj.Status.Azure.Interfaces = append(k8sObj.Status.Azure.Interfaces, *(iface.DeepCopy()))
		}
		return nil
	})
}

// PrepareIPRelease selects up to excessIPs free IPv4 addresses from the
// interface with the most releasable IPs. Interfaces are sorted by ID so the
// selection is deterministic across runs (matching the AWS path).
func (n *Node) PrepareIPRelease(excessIPs int, scopedLog *slog.Logger) *nodemanager.ReleaseAction {
	r := &nodemanager.ReleaseAction{}
	requiredIfaceName := n.k8sObj.Spec.Azure.InterfaceName
	usedIPs := n.k8sObj.Status.IPAM.Used

	n.manager.mutex.RLock()
	defer n.manager.mutex.RUnlock()

	var ifaces []*types.AzureInterface
	err := n.manager.instances.ForeachInterface(n.node.InstanceID(),
		func(_, _ string, ifaceObj ipamTypes.Interface) error {
			iface, ok := ifaceObj.(*types.AzureInterface)
			if !ok {
				return fmt.Errorf("invalid interface object")
			}
			if requiredIfaceName != "" && iface.Name != requiredIfaceName {
				return nil
			}
			ifaces = append(ifaces, iface)
			return nil
		})
	if err != nil {
		scopedLog.Warn(
			"Unable to enumerate interfaces while preparing IP release",
			logfields.InstanceID, n.node.InstanceID(),
			logfields.Error, err,
		)
		return r
	}
	slices.SortFunc(ifaces, func(a, b *types.AzureInterface) int {
		return strings.Compare(a.ID, b.ID)
	})

	for _, iface := range ifaces {
		free := freeIPsOnInterface(iface, usedIPs)
		if len(free) == 0 {
			continue
		}
		maxRelease := min(len(free), excessIPs)
		// Select the interface with the most addresses available for release.
		if r.IPsToRelease == nil || maxRelease > len(r.IPsToRelease) {
			r.InterfaceID = iface.ID
			r.PoolID = ipamTypes.PoolID(iface.Subnet.ID)
			r.IPsToRelease = free[:maxRelease]
			scopedLog.Debug(
				"Interface has unused IPs that can be released",
				logfields.ID, iface.ID,
				logfields.ExcessIPs, excessIPs,
				logfields.IPAddrs, r.IPsToRelease,
			)
		}
	}
	return r
}

// ReleaseIPPrefixes is a no-op on Azure since Azure ENIs don't
// support prefix delegation.
func (n *Node) ReleaseIPPrefixes(ctx context.Context, r *nodemanager.ReleaseAction) error {
	// nothing to do
	return nil
}

// ReleaseIPs releases r.IPsToRelease: VM NICs take IPs directly, VMSS NICs need
// them translated to IPConfiguration names. On success the IPs are dropped from
// the cached interface so the pool reflects the release before the next resync.
func (n *Node) ReleaseIPs(ctx context.Context, r *nodemanager.ReleaseAction) error {
	if len(r.IPsToRelease) == 0 {
		return nil
	}

	iface, err := n.findInterface(r.InterfaceID)
	if err != nil {
		return err
	}

	if iface.GetVMScaleSetName() == "" {
		if err := n.manager.api.UnassignPrivateIpAddressesVM(ctx, iface.Name, r.IPsToRelease); err != nil {
			return err
		}
	} else {
		names, missing := ipsToConfigNames(iface, r.IPsToRelease)
		if len(missing) > 0 {
			return fmt.Errorf("interface %s: missing IPConfiguration name mapping for IPs %v (cache out of sync, will retry after next resync)", iface.Name, missing)
		}
		if err := n.manager.api.UnassignPrivateIpAddressesVMSS(ctx, iface.GetVMID(), iface.GetVMScaleSetName(), iface.Name, names); err != nil {
			return err
		}
	}

	n.manager.RemoveIPsFromInterface(n.node.InstanceID(), r.InterfaceID, r.IPsToRelease)
	return nil
}

// freeIPsOnInterface returns the releasable IPv4 addresses on iface (Succeeded,
// non-primary, unused), sorted so truncation to excessIPs is deterministic.
func freeIPsOnInterface(iface *types.AzureInterface, used ipamTypes.AllocationMap) []string {
	free := make([]string, 0, len(iface.Addresses))
	for _, a := range iface.Addresses {
		if a.State != types.StateSucceeded {
			continue
		}
		// Release is IPv4-only.
		if !a.IP.Addr.Is4() {
			continue
		}
		// Never release the primary IPConfiguration.
		if a.IP == iface.IP {
			continue
		}
		ip := a.IP.String()
		if _, inUse := used[ip]; inUse {
			continue
		}
		free = append(free, ip)
	}
	slices.Sort(free)
	return free
}

// findInterface returns a copy of the AzureInterface with the given ID, safe to
// read without holding the manager mutex.
func (n *Node) findInterface(interfaceID string) (*types.AzureInterface, error) {
	n.manager.mutex.RLock()
	defer n.manager.mutex.RUnlock()
	iface, ok := n.manager.instances.GetInterface(n.node.InstanceID(), interfaceID)
	if !ok {
		return nil, fmt.Errorf("interface %s not found on instance %s", interfaceID, n.node.InstanceID())
	}
	azIface, ok := iface.DeepCopyInterface().(*types.AzureInterface)
	if !ok {
		return nil, fmt.Errorf("interface %s on instance %s has unexpected type", interfaceID, n.node.InstanceID())
	}
	return azIface, nil
}

// ipsToConfigNames maps each IP in ips to its IPConfiguration name on iface.
// IPs without a known mapping are returned in missing.
func ipsToConfigNames(iface *types.AzureInterface, ips []string) (names, missing []string) {
	byIP := make(map[string]string, len(iface.Addresses))
	for _, a := range iface.Addresses {
		if name := a.IPConfigName(); name != "" {
			byIP[a.IP.String()] = name
		}
	}
	for _, ip := range ips {
		if name, ok := byIP[ip]; ok {
			names = append(names, name)
		} else {
			missing = append(missing, ip)
		}
	}
	return
}

// PrepareIPAllocation returns the number of IPs that can be allocated/created.
func (n *Node) PrepareIPAllocation(scopedLog *slog.Logger) (a *nodemanager.AllocationAction, err error) {
	a = &nodemanager.AllocationAction{}
	requiredIfaceName := n.k8sObj.Spec.Azure.InterfaceName
	n.manager.mutex.RLock()
	defer n.manager.mutex.RUnlock()
	usePrimary := n.manager.usePrimary
	err = n.manager.instances.ForeachInterface(n.node.InstanceID(), func(instanceID, interfaceID string, interfaceObj ipamTypes.Interface) error {
		iface, ok := interfaceObj.(*types.AzureInterface)
		if !ok {
			return fmt.Errorf("invalid interface object")
		}

		availableOnInterface, available := isAvailableInterface(requiredIfaceName, iface, usePrimary, scopedLog)
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

// AllocateIPs performs the Azure IP allocation operation
func (n *Node) AllocateIPs(ctx context.Context, a *nodemanager.AllocationAction) error {
	iface, ok := a.Interface.(*types.AzureInterface)
	if !ok {
		return fmt.Errorf("invalid interface object")
	}

	if iface.GetVMScaleSetName() == "" {
		return n.manager.api.AssignPrivateIpAddressesVM(ctx, string(a.PoolID), iface.Name, a.IPv4.AvailableForAllocation)
	} else {
		return n.manager.api.AssignPrivateIpAddressesVMSS(ctx, iface.GetVMID(), iface.GetVMScaleSetName(), string(a.PoolID), iface.Name, a.IPv4.AvailableForAllocation)
	}
}

func (n *Node) AllocateStaticIP(ctx context.Context, staticIPTags ipamTypes.Tags) (string, error) {
	var addr netip.Addr
	var err error
	if n.vmss == "" {
		addr, err = n.manager.api.AssignPublicIPAddressesVM(ctx, n.node.InstanceID(), staticIPTags)
	} else {
		addr, err = n.manager.api.AssignPublicIPAddressesVMSS(ctx, n.node.InstanceID(), n.vmss, staticIPTags)
	}
	if err != nil {
		return "", err
	}
	return addr.String(), nil
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

	if n.node.InstanceID() == "" {
		return nil, stats, nil
	}

	available = ipamTypes.AllocationMap{}
	n.manager.mutex.RLock()
	defer n.manager.mutex.RUnlock()
	usePrimary := n.manager.usePrimary

	// Azure caps both NICs and VMs at 256 addresses; start from that ceiling
	// and decrement per NIC below for any primary slot we can't allocate.
	nodeCapacity := types.InterfaceAddressLimit
	requiredIfaceName := n.k8sObj.Spec.Azure.InterfaceName
	err = n.manager.instances.ForeachInterface(n.node.InstanceID(), func(instanceID, interfaceID string, interfaceObj ipamTypes.Interface) error {
		iface, ok := interfaceObj.(*types.AzureInterface)
		if !ok {
			return fmt.Errorf("invalid interface object")
		}

		for _, address := range iface.Addresses {
			if address.State == types.StateSucceeded {
				available[address.IP.String()] = ipamTypes.AllocationIP{Resource: interfaceID}
			} else {
				scopedLog.Warn(
					"Ignoring potentially available IP due to non-successful state",
					logfields.IPAddr, address.IP,
					logfields.State, address.State,
				)
			}
		}

		// Cache the VMSS name from the first interface we see
		if n.vmss == "" {
			n.vmss = iface.GetVMScaleSetName()
		}

		// The primary IP still consumes a NIC slot even when it is not
		// allocatable; reserve it from the VM-wide budget.
		if !usePrimary && iface.IP.IsValid() {
			nodeCapacity--
		}

		if _, isAvailable := isAvailableInterface(requiredIfaceName, iface, usePrimary, scopedLog); isAvailable {
			stats.RemainingAvailableInterfaceCount++
		}
		return nil
	})
	if err != nil {
		return nil, stats, err
	}
	stats.NodeCapacity = max(nodeCapacity, 0)

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

func (n *Node) IsPrefixDelegated() bool {
	return false
}

// GetAttachedCIDRs is a no-op since Azure does not use multi-pool but uses
// the CRD allocator.
func (n *Node) GetAttachedCIDRs() []netip.Prefix {
	return nil
}

// PrepareCIDRRelease is a no-op since Azure does not use multi-pool but uses
// the CRD allocator, that's backed by PrepareIPRelease
func (n *Node) PrepareCIDRRelease(_ []netip.Prefix) []*nodemanager.ReleaseAction {
	return nil
}

// ReleaseCIDRs is a no-op since Azure does not use multi-pool but uses the
// CRD allocator, that's backed by ReleaseIPs/ReleaseIPPrefixes
func (n *Node) ReleaseCIDRs(_ context.Context, _ *nodemanager.ReleaseAction) ([]netip.Prefix, error) {
	return nil, nil
}

// isAvailableInterface returns whether interface is available and the number of available IPs to allocate in interface
func isAvailableInterface(requiredIfaceName string, iface *types.AzureInterface, usePrimary bool, scopedLog *slog.Logger) (availableOnInterface int, available bool) {
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

	// The 256-address NIC limit covers both the primary and any secondaries.
	// When the primary is not exposed to the pool, its slot is consumed but
	// not reflected in iface.Addresses, so reserve it here.
	limit := types.InterfaceAddressLimit
	if !usePrimary && iface.IP.IsValid() {
		limit--
	}
	availableOnInterface = max(limit-len(iface.Addresses), 0)
	if availableOnInterface <= 0 {
		return 0, false
	}
	return availableOnInterface, true
}
