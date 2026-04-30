// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/stats"
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

// PrepareIPRelease prepares the release of IPs
func (n *Node) PrepareIPRelease(excessIPs int, scopedLog *slog.Logger) *ipam.ReleaseAction {
	r := &ipam.ReleaseAction{}
	requiredIfaceName := n.k8sObj.Spec.Azure.InterfaceName
	usedIPs := n.k8sObj.Status.IPAM.Used

	n.manager.mutex.RLock()
	defer n.manager.mutex.RUnlock()

	n.manager.instances.ForeachInterface(n.node.InstanceID(), func(_, _ string, obj ipamTypes.Interface) error {
		iface, ok := obj.(*types.AzureInterface)
		if !ok {
			return nil
		}
		if requiredIfaceName != "" && iface.Name != requiredIfaceName {
			return nil
		}

		var free []string
		var poolID ipamTypes.PoolID
		for _, addr := range iface.Addresses {
			if _, used := usedIPs[addr.IP]; used {
				continue
			}
			free = append(free, addr.IP)
			if poolID == "" {
				poolID = ipamTypes.PoolID(addr.Subnet)
			}
		}

		maxRelease := min(len(free), excessIPs)
		if maxRelease > len(r.IPsToRelease) {
			r.InterfaceID = iface.ID
			r.PoolID = poolID
			r.IPsToRelease = free[:maxRelease]
		}
		return nil
	})
	return r
}

// ReleaseIPPrefixes is a no-op on Azure since Azure ENIs don't
// support prefix delegation.
func (n *Node) ReleaseIPPrefixes(ctx context.Context, r *ipam.ReleaseAction) error {
	// nothing to do
	return nil
}

// ReleaseIPs performs the IP release operation
func (n *Node) ReleaseIPs(ctx context.Context, r *ipam.ReleaseAction) error {
	if len(r.IPsToRelease) == 0 {
		return nil
	}

	var iface *types.AzureInterface
	n.manager.mutex.RLock()
	n.manager.instances.ForeachInterface(n.node.InstanceID(), func(_, interfaceID string, obj ipamTypes.Interface) error {
		if interfaceID == r.InterfaceID {
			iface, _ = obj.(*types.AzureInterface)
		}
		return nil
	})
	n.manager.mutex.RUnlock()

	if iface == nil {
		return fmt.Errorf("interface %s not found for instance %s", r.InterfaceID, n.node.InstanceID())
	}

	if iface.GetVMScaleSetName() == "" {
		return n.manager.api.UnassignPrivateIpAddressesVM(ctx, iface.Name, r.IPsToRelease)
	}

	// VMSS path: the desired-state model addresses IP configurations by name, not IP.
	// Translate using the cached AzureInterface so we can skip an extra Azure API call.
	releaseSet := make(map[string]struct{}, len(r.IPsToRelease))
	for _, ip := range r.IPsToRelease {
		releaseSet[ip] = struct{}{}
	}
	ipConfigNames := make([]string, 0, len(r.IPsToRelease))
	for _, addr := range iface.Addresses {
		if _, drop := releaseSet[addr.IP]; !drop {
			continue
		}
		if addr.Name == "" {
			continue
		}
		ipConfigNames = append(ipConfigNames, addr.Name)
	}
	if len(ipConfigNames) == 0 {
		return fmt.Errorf("no cached IPConfiguration names found for IPs to release on interface %s", iface.Name)
	}

	return n.manager.api.UnassignPrivateIpAddressesVMSS(ctx, iface.GetVMID(), iface.GetVMScaleSetName(), iface.Name, ipConfigNames)
}

// PrepareIPAllocation returns the number of IPs that can be allocated/created.
func (n *Node) PrepareIPAllocation(scopedLog *slog.Logger) (a *ipam.AllocationAction, err error) {
	a = &ipam.AllocationAction{}
	requiredIfaceName := n.k8sObj.Spec.Azure.InterfaceName
	n.manager.mutex.RLock()
	defer n.manager.mutex.RUnlock()
	err = n.manager.instances.ForeachInterface(n.node.InstanceID(), func(instanceID, interfaceID string, interfaceObj ipamTypes.Interface) error {
		iface, ok := interfaceObj.(*types.AzureInterface)
		if !ok {
			return fmt.Errorf("invalid interface object")
		}

		availableOnInterface, available := isAvailableInterface(requiredIfaceName, iface, scopedLog)
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

// AllocateIPs performs the Azure IP allocation operation
func (n *Node) AllocateIPs(ctx context.Context, a *ipam.AllocationAction) error {
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
	err = n.manager.instances.ForeachInterface(n.node.InstanceID(), func(instanceID, interfaceID string, interfaceObj ipamTypes.Interface) error {
		iface, ok := interfaceObj.(*types.AzureInterface)
		if !ok {
			return fmt.Errorf("invalid interface object")
		}

		// Cache the VMSS name from the first interface we see
		if n.vmss == "" {
			n.vmss = iface.GetVMScaleSetName()
		}

		_, available := isAvailableInterface(requiredIfaceName, iface, scopedLog)
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

func (n *Node) IsPrefixDelegated() bool {
	return false
}

// isAvailableInterface returns whether interface is available and the number of available IPs to allocate in interface
func isAvailableInterface(requiredIfaceName string, iface *types.AzureInterface, scopedLog *slog.Logger) (availableOnInterface int, available bool) {
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

	availableOnInterface = max(types.InterfaceAddressLimit-len(iface.Addresses), 0)
	if availableOnInterface <= 0 {
		return 0, false
	}
	return availableOnInterface, true
}
