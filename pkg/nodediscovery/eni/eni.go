// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package eni wires the ENI-specific CiliumNode mutator (using the EC2 IMDS
// client and the AWS SDK helpers) into pkg/nodediscovery. It is imported
// (with a blank import) by the cilium-agent so that ENI IPAM works at
// runtime, while keeping the AWS SDK out of non-AWS binaries (notably
// cilium-operator-generic) which do not import this package.
package eni

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"

	awsMetadata "github.com/cilium/cilium/pkg/aws/metadata"
	awsTypes "github.com/cilium/cilium/pkg/aws/types"
	"github.com/cilium/cilium/pkg/defaults"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/nodediscovery"
)

func init() {
	nodediscovery.RegisterENIMutator(mutate)
}

// mutate populates the ENI-specific fields of nodeResource using EC2 IMDS
// metadata and the agent configuration carried in in.
func mutate(ctx context.Context, in nodediscovery.ENIMutateInputs, nodeResource *ciliumv2.CiliumNode) error {
	// set ENI field in the node only when the ENI ipam is specified
	nodeResource.Spec.ENI = awsTypes.ENISpec{}

	imds, err := awsMetadata.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("unable to create EC2 metadata client: %w", err)
	}
	info, err := imds.GetInstanceMetadata(ctx)
	if err != nil {
		return fmt.Errorf("unable to retrieve InstanceID of own EC2 instance: %w", err)
	}
	if info.InstanceID == "" {
		return errors.New("InstanceID of own EC2 instance is empty")
	}

	// It is important to determine the interface index here because this
	// function will be called when the agent is first coming up and is
	// initializing the IPAM layer (CRD allocator in this case). Later on,
	// the Operator will adjust this value based on the PreAllocate value,
	// so to ensure that the agent and the Operator are not conflicting
	// with each other, we must have similar logic to determine the
	// appropriate value to place inside the resource.
	nodeResource.Spec.ENI.VpcID = info.VPCID
	nodeResource.Spec.ENI.FirstInterfaceIndex = aws.Int(in.FirstInterfaceIndex)
	nodeResource.Spec.ENI.UsePrimaryAddress = aws.Bool(in.UsePrimaryAddress)
	nodeResource.Spec.ENI.DisablePrefixDelegation = aws.Bool(in.DisablePrefixDelegation)
	nodeResource.Spec.ENI.DeleteOnTermination = aws.Bool(in.DeleteOnTermination)

	nodeResource.Spec.ENI.SubnetIDs = in.SubnetIDs
	nodeResource.Spec.ENI.SubnetTags = in.SubnetTags
	nodeResource.Spec.ENI.SecurityGroups = in.SecurityGroups
	nodeResource.Spec.ENI.SecurityGroupTags = in.SecurityGroupTags
	nodeResource.Spec.ENI.ExcludeInterfaceTags = in.ExcludeInterfaceTags

	nodeResource.Spec.IPAM.MinAllocate = in.IPAMMinAllocate
	nodeResource.Spec.IPAM.PreAllocate = in.IPAMPreAllocate
	nodeResource.Spec.IPAM.MaxAllocate = in.IPAMMaxAllocate

	if c := in.CNIConfigManager.GetCustomNetConf(); c != nil {
		if c.IPAM.MinAllocate != 0 {
			nodeResource.Spec.IPAM.MinAllocate = c.IPAM.MinAllocate
		}
		if c.IPAM.PreAllocate != 0 {
			nodeResource.Spec.IPAM.PreAllocate = c.IPAM.PreAllocate
		}
		if c.ENI.FirstInterfaceIndex != nil {
			nodeResource.Spec.ENI.FirstInterfaceIndex = c.ENI.FirstInterfaceIndex
		}
		if len(c.ENI.SecurityGroups) > 0 {
			nodeResource.Spec.ENI.SecurityGroups = c.ENI.SecurityGroups
		}
		if len(c.ENI.SecurityGroupTags) > 0 {
			nodeResource.Spec.ENI.SecurityGroupTags = c.ENI.SecurityGroupTags
		}
		if len(c.ENI.SubnetIDs) > 0 {
			nodeResource.Spec.ENI.SubnetIDs = c.ENI.SubnetIDs
		}
		if len(c.ENI.SubnetTags) > 0 {
			nodeResource.Spec.ENI.SubnetTags = c.ENI.SubnetTags
		}
		if c.ENI.VpcID != "" {
			nodeResource.Spec.ENI.VpcID = c.ENI.VpcID
		}
		if len(c.ENI.ExcludeInterfaceTags) > 0 {
			nodeResource.Spec.ENI.ExcludeInterfaceTags = c.ENI.ExcludeInterfaceTags
		}
		if c.ENI.UsePrimaryAddress != nil {
			nodeResource.Spec.ENI.UsePrimaryAddress = c.ENI.UsePrimaryAddress
		}
		if c.ENI.DisablePrefixDelegation != nil {
			nodeResource.Spec.ENI.DisablePrefixDelegation = c.ENI.DisablePrefixDelegation
		}
		nodeResource.Spec.ENI.DeleteOnTermination = c.ENI.DeleteOnTermination
	}

	seedPoolRequest(nodeResource, in)

	nodeResource.Spec.InstanceID = info.InstanceID
	nodeResource.Spec.ENI.InstanceType = info.InstanceType
	nodeResource.Spec.ENI.AvailabilityZone = info.AvailabilityZone
	nodeResource.Spec.ENI.NodeSubnetID = info.SubnetID
	return nil
}

// seedPoolRequest populates the "default" pool entry of
// Spec.IPAM.Pools.Requested with the demand implied by the agent
// configuration, unless the IPAM layer has already published a demand of its
// own.
//
// The IPAM layer only writes Spec.IPAM.Pools.Requested once the restoration of
// the local IPs has finished, which happens well after the CiliumNode resource
// is first created. The operator does not know which address families this node
// wants until then, and falls back to its pre-1.20 behavior of pre-allocating
// min-allocate IPv4 addresses, even for a node running in IPv6-only mode.
// Seeding the demand closes that window: the operator honors the enabled
// families from the very first reconciliation onwards.
func seedPoolRequest(nodeResource *ciliumv2.CiliumNode, in nodediscovery.ENIMutateInputs) {
	for _, req := range nodeResource.Spec.IPAM.Pools.Requested {
		if req.Pool == defaults.IPAMDefaultIPPool {
			return
		}
	}

	// No address is in use yet, so the linear pre-allocation formula used by
	// the IPAM layer (inUse + preAllocate) boils down to preAllocate.
	preAllocate := nodeResource.Spec.IPAM.PreAllocate
	if preAllocate == 0 {
		preAllocate = defaults.IPAMPreAllocation
	}

	var needed ipamTypes.IPAMPoolDemand
	if in.EnableIPv4 {
		needed.IPv4Addrs = preAllocate
	}
	if in.EnableIPv6 {
		needed.IPv6Addrs = preAllocate
	}
	if needed.IPv4Addrs == 0 && needed.IPv6Addrs == 0 {
		return
	}

	nodeResource.Spec.IPAM.Pools.Requested = append(nodeResource.Spec.IPAM.Pools.Requested,
		ipamTypes.IPAMPoolRequest{
			Pool:   defaults.IPAMDefaultIPPool,
			Needed: needed,
		})
}
