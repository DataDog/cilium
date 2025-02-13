// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/oracle/types"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/ipam"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/oracle/api"
	"github.com/cilium/cilium/pkg/time"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "oracle-instances-manager")

// InstancesManager maintains the list of instances. It must be kept up to date
// by calling resync() regularly.
type InstancesManager struct {
	mutex      lock.RWMutex
	resyncLock lock.RWMutex
	instances  *ipamTypes.InstanceMap
	vcnId      string
	vcn        ipamTypes.VirtualNetwork
	subnets    ipamTypes.SubnetMap
	api        api.OracleClient
}

// NewInstancesManager returns a new instances manager
func NewInstancesManager(api api.OracleClient, vcnId string) *InstancesManager {
	return &InstancesManager{
		instances: ipamTypes.NewInstanceMap(),
		api:       api,
		vcnId:     vcnId,
	}
}

// CreateNode is called on discovery of a new node
func (m *InstancesManager) CreateNode(obj *v2.CiliumNode, n *ipam.Node) ipam.NodeOperations {
	return &Node{manager: m, node: n}
}

// HasInstance returns whether the instance is in instances
func (m *InstancesManager) HasInstance(instanceID string) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.instances.Exists(instanceID)
}

// GetPoolQuota returns the number of available IPs in all IP pools
func (m *InstancesManager) GetPoolQuota() (quota ipamTypes.PoolQuotaMap) {
	m.mutex.RLock()
	pool := ipamTypes.PoolQuotaMap{}
	for subnetID, subnet := range m.subnets {
		pool[ipamTypes.PoolID(subnetID)] = ipamTypes.PoolQuota{
			AvailableIPs: subnet.AvailableAddresses,
		}
	}
	m.mutex.RUnlock()
	return pool
}

// Resync fetches the list of Oracle instances and subnets and updates the local
// cache in the instanceManager. It returns the time when the resync has
// started or time.Time{} if it did not complete.
func (m *InstancesManager) Resync(ctx context.Context) time.Time {
	// Full API resync should block the instance incremental resync from all nodes.
	m.resyncLock.Lock()
	defer m.resyncLock.Unlock()
	// An empty instanceID indicates the full resync.
	return m.resync(ctx, "")
}

func (m *InstancesManager) resync(ctx context.Context, instanceID string) time.Time {
	resyncStart := time.Now()

	vcn, err := m.api.GetVcn(ctx, m.vcnId)
	if err != nil {
		log.WithError(err).Warning("Unable to synchronize Oracle VCN")
		return time.Time{}
	}

	subnets, err := m.api.GetSubnets(ctx, vcn)
	if err != nil {
		log.WithError(err).Warning("Unable to synchronize Oracle Subnets")
		return time.Time{}
	}

	if instanceID == "" {
		instances, err := m.api.GetInstances(ctx, vcn, subnets)
		if err != nil {
			log.WithError(err).Warning("Unable to synchronize Oracle Instances")
			return time.Time{}
		}

		log.WithFields(logrus.Fields{
			"vcnID":        vcn.ID,
			"numSubnets":   len(subnets),
			"numInstances": instances.NumInstances(),
		}).Info("Synchronized Oracle IPAM information (full resync)")

		m.mutex.Lock()
		defer m.mutex.Unlock()
		m.instances = instances
	} else {
		instance, err := m.api.GetInstance(ctx, vcn, subnets, instanceID)
		if err != nil {
			log.WithError(err).Warning("Unable to synchronize Oracle Instance ", instanceID)
			return time.Time{}
		}

		log.WithFields(logrus.Fields{
			"vcnID":      vcn.ID,
			"numSubnets": len(subnets),
			"instanceID": instanceID,
		}).Info("Synchronized Oracle IPAM information (incremental resync)")

		m.mutex.Lock()
		defer m.mutex.Unlock()
		m.instances.UpdateInstance(instanceID, instance)
	}

	m.vcn = vcn
	m.subnets = subnets

	return resyncStart
}

func (m *InstancesManager) InstanceSync(ctx context.Context, instanceID string) time.Time {
	m.resyncLock.RLock()
	defer m.resyncLock.RUnlock()
	return m.resync(ctx, instanceID)
}

// DeleteInstance delete instance from m.instances
func (m *InstancesManager) DeleteInstance(instanceID string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.instances.Delete(instanceID)
}

func (m *InstancesManager) UpdateInterface(instanceID string, vnic *types.OracleInterface) {
	m.mutex.Lock()
	interfaceRevision := ipamTypes.InterfaceRevision{Resource: vnic}
	m.instances.Update(instanceID, interfaceRevision)
	m.mutex.Unlock()
}

func (m *InstancesManager) FindSubnetByTags(requiredTags ipamTypes.Tags) (bestSubnet *ipamTypes.Subnet) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	for _, s := range m.subnets {
		if s.VirtualNetworkID == m.vcnId && s.Tags.Match(requiredTags) {
			if bestSubnet == nil || bestSubnet.AvailableAddresses < s.AvailableAddresses {
				bestSubnet = s
			}
		}
	}

	return
}
