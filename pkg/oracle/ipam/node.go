// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/stats"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/math"
	"github.com/cilium/cilium/pkg/oracle/types"
)

type ipamNodeActions interface {
	InstanceID() string
}

// Node represents a node representing an oracle instance
type Node struct {
	// k8sObj is the CiliumNode custom resource representing the node
	k8sObj *v2.CiliumNode

	// node contains the general purpose fields of a node
	node ipamNodeActions

	// manager is the oracle node manager responsible for this node
	manager *InstancesManager

	mutex lock.RWMutex
}

// UpdatedNode is called when an update to the CiliumNode is received.
func (n *Node) UpdatedNode(obj *v2.CiliumNode) {
	n.k8sObj = obj
}

// PopulateStatusFields fills in the status field of the CiliumNode custom
// resource with Oracle specific information
func (n *Node) PopulateStatusFields(k8sObj *v2.CiliumNode) {
	k8sObj.Status.Oracle.Interfaces = []types.OracleInterface{}
	n.manager.mutex.RLock()
	defer n.manager.mutex.RUnlock()

	err := n.manager.instances.ForeachInterface(n.node.InstanceID(), func(instanceID, interfaceID string, interfaceObj ipamTypes.InterfaceRevision) error {
		iface, ok := interfaceObj.Resource.(*types.OracleInterface)
		if ok {
			k8sObj.Status.Oracle.Interfaces = append(k8sObj.Status.Oracle.Interfaces, *(iface.DeepCopy()))
		}
		return nil
	})
	if err != nil {
		return
	}
}

// PrepareIPRelease prepares the release of IPs
func (n *Node) PrepareIPRelease(excessIPs int, scopedLog *logrus.Entry) *ipam.ReleaseAction {
	r := &ipam.ReleaseAction{}

	n.mutex.RLock()
	defer n.mutex.RUnlock()

	// Iterate over VNICs on this node, select the VNIC with the most
	// addresses available for release
	err := n.manager.instances.ForeachInterface(n.node.InstanceID(), func(instanceID, interfaceID string, interfaceObj ipamTypes.InterfaceRevision) error {
		iface, ok := interfaceObj.Resource.(*types.OracleInterface)
		if !ok {
			return fmt.Errorf("invalid interface object")
		}

		if iface.IsPrimary {
			return nil
		}

		// Count free IP addresses on this VNIC
		// Keep track of IP OCIDs because they will be needed to actually delete the IPs
		var freeIpIds []string
		for _, ip := range iface.SecondaryIPs {
			_, ipUsed := n.k8sObj.Status.IPAM.Used[ip.IP]
			if !ipUsed {
				freeIpIds = append(freeIpIds, ip.ID)
			}
		}
		if len(freeIpIds) <= 0 {
			return nil
		}

		ipsToRelease := math.IntMin(len(freeIpIds), excessIPs)
		r.InterfaceID = iface.ID
		r.PoolID = ipamTypes.PoolID(iface.SubnetID)
		r.IPsToRelease = freeIpIds[:ipsToRelease]

		return nil
	})

	if err != nil {
		return nil
	}

	return r
}

// ReleaseIPs performs the IP release operation
func (n *Node) ReleaseIPs(ctx context.Context, r *ipam.ReleaseAction) error {
	for _, ipId := range r.IPsToRelease {
		err := n.manager.api.DeletePrivateIpAddress(ctx, ipId)
		if err != nil {
			return err
		}
	}

	return nil
}

// PrepareIPAllocation returns the number of IPs that can be allocated/created.
func (n *Node) PrepareIPAllocation(scopedLog *logrus.Entry) (a *ipam.AllocationAction, err error) {
	a = &ipam.AllocationAction{}
	n.manager.mutex.RLock()
	defer n.manager.mutex.RUnlock()

	a.EmptyInterfaceSlots = n.k8sObj.Spec.Oracle.MaxVnicAttachments - 1
	numInterfaces := n.manager.instances.NumInterfaces(n.node.InstanceID())
	if numInterfaces == 1 {
		// This instance only has a primary interface
		// We need to allocate a secondary interface first
		scopedLog.Info("No secondary interfaces available, creating a new one")
		return
	}

	err = n.manager.instances.ForeachInterface(n.node.InstanceID(), func(instanceID, interfaceID string, interfaceObj ipamTypes.InterfaceRevision) error {
		iface, ok := interfaceObj.Resource.(*types.OracleInterface)
		if !ok {
			return fmt.Errorf("invalid interface object")
		}

		// Skip the primary interface
		if iface.IsPrimary {
			return nil
		}

		// Count the number of available IPs on the secondary interface
		// -1 is for the primary IP
		availableOnInterface := types.InterfaceAddressLimit - len(iface.SecondaryIPs) - 1
		scopedLog.Debug("Available IPs on interface ", interfaceID, ": ", availableOnInterface)
		if availableOnInterface <= 0 {
			return nil
		}
		a.IPv4.InterfaceCandidates++
		a.EmptyInterfaceSlots--

		if subnet := n.manager.subnets[iface.SubnetID]; subnet != nil {
			// TODO choose the iface with the most available IPs?
			if subnet.AvailableAddresses > 0 && a.InterfaceID == "" {
				a.InterfaceID = iface.ID
				a.PoolID = ipamTypes.PoolID(subnet.ID)
				a.IPv4.AvailableForAllocation = math.IntMin(subnet.AvailableAddresses, availableOnInterface)
			}
		}

		return nil
	})

	return
}

// AllocateIPs performs the Azure IP allocation operation
func (n *Node) AllocateIPs(ctx context.Context, a *ipam.AllocationAction) error {
	for i := 0; i < a.IPv4.AvailableForAllocation; i++ {
		_, err := n.manager.api.AssignPrivateIpAddress(ctx, a.InterfaceID)
		if err != nil {
			return err
		}
	}

	return nil
}

func (n *Node) AllocateStaticIP(ctx context.Context, staticIPTags ipamTypes.Tags) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (n *Node) CreateInterface(ctx context.Context, allocation *ipam.AllocationAction, scopedLog *logrus.Entry) (int, string, error) {
	// availabilityDomain := n.k8sObj.Spec.Oracle.AvailabilityDomain
	// TODO how to manage regional subnets?
	subnetTags := n.k8sObj.Spec.Oracle.SubnetTags

	subnet := n.manager.FindSubnetByTags(subnetTags)
	if subnet == nil {
		return 0,
			"unable to find subnet", // TODO make this a const?
			fmt.Errorf(
				"no matching subnet available for interface creation (SubnetTags=%s)",
				subnetTags,
			)
	}
	scopedLog.WithFields(logrus.Fields{
		"subnetID": subnet.ID,
		"tags":     subnet.Tags,
	}).Info("Found subnet for the interface")
	allocation.PoolID = ipamTypes.PoolID(subnet.ID)

	// TODO security groups?

	// Must allocate secondary VNIC IPs as needed, up to the limit (subtract 1 because it's automatically used for the primary IP)
	toAllocate := math.IntMin(allocation.IPv4.MaxIPsToAllocate, types.InterfaceAddressLimit-1)
	scopedLog.Info("Will allocate ", toAllocate, " IPs to VNIC")
	// Validate whether request has already been fulfilled in the meantime
	if toAllocate == 0 {
		return 0, "", nil
	}

	vnic, err := n.manager.api.AttachVnic(ctx, n.node.InstanceID(), subnet)
	if err != nil {
		return 0, "unable to attach VNIC", err
	}

	defer n.manager.instances.Update(n.node.InstanceID(), ipamTypes.InterfaceRevision{Resource: vnic})

	for i := 0; i < toAllocate; i++ {
		ip, err := n.manager.api.AssignPrivateIpAddress(ctx, vnic.ID)
		if err != nil {
			return i, "unable to allocate all IPs to VNIC", err
		}
		vnic.SecondaryIPs = append(vnic.SecondaryIPs, ip)
	}

	return toAllocate, "", nil
}

// ResyncInterfacesAndIPs is called to retrieve interfaces and IPs known to the Oracle API and return them
func (n *Node) ResyncInterfacesAndIPs(ctx context.Context, scopedLog *logrus.Entry) (available ipamTypes.AllocationMap, stats stats.InterfaceStats, err error) {

	if n.node.InstanceID() == "" {
		return nil, stats, nil
	}

	available = ipamTypes.AllocationMap{}
	n.manager.mutex.RLock()
	defer n.manager.mutex.RUnlock()

	stats.NodeCapacity = n.GetMaximumAllocatableIPv4()
	// Only count the secondary VNICs
	stats.RemainingAvailableInterfaceCount = n.k8sObj.Spec.Oracle.MaxVnicAttachments - 1

	n.manager.instances.ForeachInterface(n.node.InstanceID(), func(instanceID, interfaceID string, interfaceObj ipamTypes.InterfaceRevision) error {
		iface, ok := interfaceObj.Resource.(*types.OracleInterface)
		if !ok {
			scopedLog.WithField("interfaceID", interfaceID).Warning("Not an Oracle interface object, ignoring interface")
			return nil
		}

		// Ignore the primary interface
		if iface.IsPrimary {
			return nil
		}

		// Check if the secondary interface is at capacity
		if iface.IsMaximumIPCapacityReached() {
			scopedLog.WithField("interfaceID", interfaceID).Info("Secondary interface is at capacity")
			stats.RemainingAvailableInterfaceCount--
		}

		// Count the primary IP + the secondary IPs
		available[iface.IP] = ipamTypes.AllocationIP{Resource: interfaceID}
		for _, ip := range iface.SecondaryIPs {
			available[ip.IP] = ipamTypes.AllocationIP{Resource: interfaceID}
		}
		scopedLog.Debug("available IPs on interface ", interfaceID, ": ", available)

		return nil
	})

	return available, stats, nil
}

// GetMaximumAllocatableIPv4 returns the maximum amount of IPv4 addresses
// that can be allocated to the instance
func (n *Node) GetMaximumAllocatableIPv4() int {
	// Count the number of IPs we can allocate on all secondary VNICs
	return (n.k8sObj.Spec.Oracle.MaxVnicAttachments - 1) * types.InterfaceAddressLimit
}

// GetMinimumAllocatableIPv4 returns the minimum amount of IPv4 addresses that
// must be allocated to the instance.
func (n *Node) GetMinimumAllocatableIPv4() int {
	return defaults.IPAMPreAllocation
}

func (n *Node) IsPrefixDelegated() bool {
	return false
}

func (n *Node) GetUsedIPWithPrefixes() int {
	if n.k8sObj == nil {
		return 0
	}
	return len(n.k8sObj.Status.IPAM.Used)
}
