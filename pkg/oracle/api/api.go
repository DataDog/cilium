// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"fmt"
	"github.com/cilium/cilium/pkg/cidr"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/oracle/types"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/version"
	"github.com/sirupsen/logrus"
	"os"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

var (
	log       = logging.DefaultLogger.WithField(logfields.LogSubsys, "oracle-api")
	userAgent = fmt.Sprintf("cilium/%s", version.Version)
)

type OracleClient struct {
	computeClient core.ComputeClient
	networkClient core.VirtualNetworkClient
	compartmentID string
}

func NewClient(compartmentID string) (*OracleClient, error) {
	// TODO setup auth
	// auth.InstancePrincipalConfigurationProvider()
	config, err := common.ConfigurationProviderFromFile("/oracle/.oci/config", "")
	if err != nil {
		return nil, err
	}
	retryPolicy := common.DefaultRetryPolicyWithoutEventualConsistency()
	err = os.Setenv("OCI_SDK_APPEND_USER_AGENT", userAgent)
	if err != nil {
		log.WithError(err).Warn("Failed to set the user agent for the Oracle SDK")
	}

	computeClient, err := core.NewComputeClientWithConfigurationProvider(config)
	if err != nil {
		return nil, err
	}
	computeClient.SetCustomClientConfiguration(common.CustomClientConfiguration{
		RetryPolicy: &retryPolicy,
	})

	networkClient, err := core.NewVirtualNetworkClientWithConfigurationProvider(config)
	if err != nil {
		return nil, err
	}
	networkClient.SetCustomClientConfiguration(common.CustomClientConfiguration{
		RetryPolicy: &retryPolicy,
	})

	log.Debug("Successfully instantiated Oracle clients")

	return &OracleClient{
		computeClient: computeClient,
		networkClient: networkClient,
		compartmentID: compartmentID,
	}, nil
}

func (c *OracleClient) GetVcn(ctx context.Context, vcnId string) (ipamTypes.VirtualNetwork, error) {
	getVcnResponse, err := c.networkClient.GetVcn(ctx, core.GetVcnRequest{
		VcnId: common.String(vcnId),
	})
	if err != nil {
		return ipamTypes.VirtualNetwork{}, err
	}
	log.Debug("GetVcn: response: ", getVcnResponse.String())

	vcn := ipamTypes.VirtualNetwork{
		ID: *getVcnResponse.Id,
	}
	vcn.PrimaryCIDR = getVcnResponse.CidrBlocks[0]

	// If there are more elements, add them to secondary CIDRs
	if len(getVcnResponse.CidrBlocks) > 1 {
		for _, cidrBlock := range getVcnResponse.CidrBlocks[1:] {
			vcn.CIDRs = append(vcn.CIDRs, cidrBlock)
		}
	}

	return vcn, nil
}

/*
func (c *OracleClient) GetVcns(ctx context.Context) (ipamTypes.VirtualNetworkMap, error) {
	vcns := ipamTypes.VirtualNetworkMap{}

	// TODO Get instead of List
	listVcnsResponse, err := c.networkClient.ListVcns(ctx, core.ListVcnsRequest{
		// TODO
		CompartmentId:  common.String(""),
		LifecycleState: core.VcnLifecycleStateAvailable,
	})
	if err != nil {
		return nil, err
	}

	for _, vcn := range listVcnsResponse.Items {
		v := ipamTypes.VirtualNetwork{
			ID: *vcn.Id,
		}
		// The first element is the primary CIDR
		v.PrimaryCIDR = vcn.CidrBlocks[0]

		// If there are more elements, add them to secondary CIDRs
		if len(vcn.CidrBlocks) > 1 {
			for _, cidrBlock := range vcn.CidrBlocks[1:] {
				v.CIDRs = append(v.CIDRs, cidrBlock)
			}
		}
		vcns[*vcn.Id] = &v
	}

	return vcns, nil
}
*/

func (c *OracleClient) GetSubnets(ctx context.Context, vcn ipamTypes.VirtualNetwork) (ipamTypes.SubnetMap, error) {
	subnets := ipamTypes.SubnetMap{}

	listSubnetsResponse, err := c.networkClient.ListSubnets(ctx, core.ListSubnetsRequest{
		CompartmentId:  common.String(c.compartmentID),
		LifecycleState: core.SubnetLifecycleStateAvailable,
		VcnId:          common.String(vcn.ID),
	})
	if err != nil {
		return nil, err
	}

	log.Debug("GetSubnets: response: ", listSubnetsResponse.String())

	for _, subnet := range listSubnetsResponse.Items {
		s := ipamTypes.Subnet{
			ID: *subnet.Id,
		}
		if subnet.DisplayName != nil {
			s.Name = *subnet.DisplayName
		}
		s.CIDR, err = cidr.ParseCIDR(*subnet.CidrBlock)
		if err != nil {
			return nil, err
		}
		if subnet.AvailabilityDomain != nil {
			s.AvailabilityZone = *subnet.AvailabilityDomain
		} else {
			s.AvailabilityZone = "regional"
		}

		s.VirtualNetworkID = *subnet.VcnId
		s.Tags = subnet.FreeformTags
		// 3 IPs are reserved by Oracle
		// https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/overview.htm#Allowed
		totalIps := s.CIDR.AvailableIPs() - 3

		// TODO paging
		// GetSubnetCidrUtilization() could be a less accurate but cheaper alternative
		subnetIpInventoryResponse, err := c.networkClient.GetSubnetIpInventory(ctx, core.GetSubnetIpInventoryRequest{
			SubnetId: subnet.Id,
		})
		if err != nil {
			return nil, err
		}
		log.Debug("GetSubnets: subnetIpInventoryResponse: ", subnetIpInventoryResponse.String())
		usedIps := *subnetIpInventoryResponse.Count
		s.AvailableAddresses = totalIps - usedIps

		subnets[s.ID] = &s
	}

	return subnets, nil
}

func (c *OracleClient) generateOracleInterface(vnicAttachment core.VnicAttachment, vcn ipamTypes.VirtualNetwork, subnet ipamTypes.Subnet) (types.OracleInterface, error) {
	iface := types.OracleInterface{
		ID:                 *vnicAttachment.VnicId,
		InstanceID:         *vnicAttachment.InstanceId,
		SubnetID:           subnet.ID,
		SubnetCIDR:         subnet.CIDR.String(),
		AvailabilityDomain: *vnicAttachment.AvailabilityDomain,
		VCN: types.OracleVCN{
			PrimaryCIDR:    vcn.PrimaryCIDR,
			SecondaryCIDRs: vcn.CIDRs,
		},
	}

	vnic, err := c.networkClient.GetVnic(context.Background(), core.GetVnicRequest{
		VnicId: vnicAttachment.VnicId,
	})
	if err != nil {
		return types.OracleInterface{}, err
	}
	log.Debug("generateOracleInterface: vnic: ", vnic.String())
	iface.IsPrimary = *vnic.IsPrimary
	iface.MAC = *vnic.MacAddress
	iface.SecurityGroupIds = vnic.NsgIds

	ips, err := c.networkClient.ListPrivateIps(context.Background(), core.ListPrivateIpsRequest{
		VnicId: vnicAttachment.VnicId,
	})
	if err != nil {
		return types.OracleInterface{}, err
	}
	log.Debug("generateOracleInterface: ips: ", ips.String())
	for _, ip := range ips.Items {
		// TODO error handling
		if ip.IsPrimary != nil && *ip.IsPrimary {
			iface.IP = *ip.IpAddress
		} else {
			iface.SecondaryIPs = append(iface.SecondaryIPs, types.OracleIP{
				ID: *ip.Id,
				IP: *ip.IpAddress,
			})
		}
	}

	return iface, nil
}

func (c *OracleClient) GetInstances(ctx context.Context, vcn ipamTypes.VirtualNetwork, subnets ipamTypes.SubnetMap) (*ipamTypes.InstanceMap, error) {
	instances := ipamTypes.NewInstanceMap()

	request := core.ListVnicAttachmentsRequest{
		CompartmentId: common.String(c.compartmentID),
		Limit:         common.Int(500),
	}

	vnicAttachmentsResponse, err := c.computeClient.ListVnicAttachments(ctx, request)
	for {
		if err != nil {
			return nil, err
		}
		log.Debug("GetInstances: vnicAttachmentsResponse: ", vnicAttachmentsResponse.String())

		for _, vnicAttachment := range vnicAttachmentsResponse.Items {
			if vnicAttachment.LifecycleState != core.VnicAttachmentLifecycleStateAttached {
				log.Info("Skipping VNIC ", *vnicAttachment.VnicId, " because it is not attached")
				continue
			}
			// Check if VNIC subnet is part of known subnets
			if _, ok := subnets[*vnicAttachment.SubnetId]; !ok {
				log.Info("Skipping VNIC ", *vnicAttachment.VnicId, " because subnet ", *vnicAttachment.SubnetId, " is not part of known subnets")
				continue
			}

			iface, err := c.generateOracleInterface(vnicAttachment, vcn, *subnets[*vnicAttachment.SubnetId])
			if err != nil {
				return nil, err
			}

			instances.Update(*vnicAttachment.InstanceId, ipamTypes.InterfaceRevision{Resource: &iface})
		}

		if vnicAttachmentsResponse.OpcNextPage != nil {
			request.Page = vnicAttachmentsResponse.OpcNextPage
			vnicAttachmentsResponse, err = c.computeClient.ListVnicAttachments(ctx, request)
		} else {
			// No more pages, break the loop
			break
		}
	}

	return instances, nil
}

func (c *OracleClient) GetInstance(ctx context.Context, vcn ipamTypes.VirtualNetwork, subnets ipamTypes.SubnetMap, instanceID string) (*ipamTypes.Instance, error) {
	instance := ipamTypes.Instance{}
	instance.Interfaces = map[string]ipamTypes.InterfaceRevision{}

	vnicAttachmentsResponse, err := c.computeClient.ListVnicAttachments(ctx, core.ListVnicAttachmentsRequest{
		CompartmentId: common.String(c.compartmentID),
		InstanceId:    common.String(instanceID),
	})
	if err != nil {
		return nil, err
	}
	log.Debug("GetInstance: vnicAttachmentsResponse: ", vnicAttachmentsResponse.String())

	for _, vnicAttachment := range vnicAttachmentsResponse.Items {
		if vnicAttachment.LifecycleState != core.VnicAttachmentLifecycleStateAttached {
			log.WithField("vnicID", *vnicAttachment.VnicId).Info("Skipping VNIC because it is not attached")
			continue
		}
		// Check if VNIC subnet is part of known subnets
		if _, ok := subnets[*vnicAttachment.SubnetId]; !ok {
			log.WithField("vnicID", *vnicAttachment.VnicId).Info("Skipping VNIC because subnet ", *vnicAttachment.SubnetId, " is not part of known subnets")
			continue
		}

		iface, err := c.generateOracleInterface(vnicAttachment, vcn, *subnets[*vnicAttachment.SubnetId])
		if err != nil {
			return nil, err
		}

		instance.Interfaces[iface.ID] = ipamTypes.InterfaceRevision{
			Resource: &iface,
		}
	}

	return &instance, nil
}

func (c *OracleClient) AttachVnic(ctx context.Context, instanceId string, subnet ipamTypes.Subnet, nsgIds []string) (*types.OracleInterface, error) {
	attachVnicResponse, err := c.computeClient.AttachVnic(ctx, core.AttachVnicRequest{
		AttachVnicDetails: core.AttachVnicDetails{
			InstanceId:  common.String(instanceId),
			DisplayName: common.String("cilium-managed-vnic-attachment"),
			CreateVnicDetails: &core.CreateVnicDetails{
				SubnetId:    common.String(subnet.ID),
				NsgIds:      nsgIds,
				DisplayName: common.String("cilium-managed-vnic"),
				FreeformTags: map[string]string{
					"cilium-managed": "true",
				},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	log.Debug("AttachVnic: response: ", attachVnicResponse.String())

	vnicAttachmentState := attachVnicResponse.LifecycleState
	var vnicID string

	if vnicAttachmentState == core.VnicAttachmentLifecycleStateAttached && attachVnicResponse.VnicId != nil {
		vnicID = *attachVnicResponse.VnicId
	} else {
		for vnicAttachmentState != core.VnicAttachmentLifecycleStateAttached {
			time.Sleep(2 * time.Second) // TODO make this a const
			// TODO limit the number of retries

			getVnicAttachmentResponse, err := c.computeClient.GetVnicAttachment(ctx, core.GetVnicAttachmentRequest{
				VnicAttachmentId: attachVnicResponse.Id,
			})
			if err != nil {
				// TODO rollback
				return nil, err
			}
			log.Debug("AttachVnic: getVnicAttachmentResponse: ", getVnicAttachmentResponse.String())

			if getVnicAttachmentResponse.LifecycleState == core.VnicAttachmentLifecycleStateAttached && getVnicAttachmentResponse.VnicId != nil {
				vnicID = *getVnicAttachmentResponse.VnicId
				break
			}
		}
	}

	iface := types.OracleInterface{
		ID:                 vnicID,
		IsPrimary:          false,
		InstanceID:         instanceId,
		SubnetID:           subnet.ID,
		SubnetCIDR:         subnet.CIDR.String(),
		AvailabilityDomain: *attachVnicResponse.AvailabilityDomain,
	}

	// Get the VNIC to find its primary IP
	vnic, err := c.networkClient.GetVnic(ctx, core.GetVnicRequest{
		VnicId: common.String(vnicID),
	})
	if err != nil {
		return nil, err
	}
	log.Debug("AttachVnic: GetVnic: ", vnic.String())

	if vnic.PrivateIp != nil {
		iface.IP = *vnic.PrivateIp
	} else {
		return nil, fmt.Errorf("private IP nil, shouldn't happen")
	}
	iface.MAC = *vnic.MacAddress
	iface.SecurityGroupIds = vnic.NsgIds

	log.WithFields(logrus.Fields{
		"vnicID":     vnicID,
		"instanceID": instanceId,
	}).Info("Successfully created VNIC and attached to instance")

	return &iface, nil
}

func (c *OracleClient) AssignPrivateIpAddress(ctx context.Context, vnicId string) (types.OracleIP, error) {
	createPrivateIpResponse, err := c.networkClient.CreatePrivateIp(ctx, core.CreatePrivateIpRequest{
		CreatePrivateIpDetails: core.CreatePrivateIpDetails{
			VnicId:      common.String(vnicId),
			DisplayName: common.String("cilium-managed-ip"),
			FreeformTags: map[string]string{
				"cilium-managed": "true",
			},
		},
	})
	if err != nil {
		return types.OracleIP{}, err
	}
	log.Debug("AssignPrivateIpAddress: response: ", createPrivateIpResponse.String())
	log.WithFields(logrus.Fields{
		"vnicID": vnicId,
		"ip":     *createPrivateIpResponse.IpAddress,
	}).Info("Successfully assigned IP to VNIC")

	return types.OracleIP{
		ID: *createPrivateIpResponse.Id,
		IP: *createPrivateIpResponse.IpAddress,
	}, nil
}

func (c *OracleClient) DeletePrivateIpAddress(ctx context.Context, ipId string) error {
	_, err := c.networkClient.DeletePrivateIp(ctx, core.DeletePrivateIpRequest{
		PrivateIpId: common.String(ipId),
	})
	if err != nil {
		return err
	}
	log.WithField("ipId", ipId).Info("Successfully deleted IP ")
	return nil
}
