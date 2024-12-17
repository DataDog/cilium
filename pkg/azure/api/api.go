// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/Azure/go-autorest/autorest/azure"
	"k8s.io/apimachinery/pkg/util/rand"

	"github.com/cilium/cilium/pkg/api/helpers"
	"github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/cidr"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/spanstat"
	"github.com/cilium/cilium/pkg/version"
)

const (
	interfacesCreateOrUpdate        = "Interfaces.CreateOrUpdate"
	interfacesGet                   = "Interfaces.Get"
	interfacesListAll               = "Interfaces.ListAll"
	interfacesListComplete          = "Interfaces.ListComplete"
	virtualMachineScaleSetsListAll  = "VirtualMachineScaleSets.ListAll"
	virtualMachineScaleSetVMsGet    = "VirtualMachineScaleSetVMs.Get"
	virtualMachineScaleSetVMsUpdate = "VirtualMachineScaleSetVMs.Update"
	virtualNetworksList             = "VirtualNetworks.List"
	virtualnetworksListAll          = "Virtualnetworks.ListAll"

	interfacesListVirtualMachineScaleSetNetworkInterfacesComplete = "Interfaces.ListVirtualMachineScaleSetNetworkInterfacesComplete"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "azure-api")
)

// Client represents an Azure API client
type Client struct {
	resourceGroup   string
	interfaces      *armnetwork.InterfacesClient
	virtualnetworks *armnetwork.VirtualNetworksClient
	vmss            *armcompute.VirtualMachineScaleSetVMsClient
	vmscalesets     *armcompute.VirtualMachineScaleSetsClient
	limiter         *helpers.APILimiter
	metricsAPI      MetricsAPI
	usePrimary      bool
}

// MetricsAPI represents the metrics maintained by the Azure API client
type MetricsAPI interface {
	ObserveAPICall(call, status string, duration float64)
	ObserveRateLimit(operation string, duration time.Duration)
}

// net/http Client with a custom cilium user agent
type httpClient struct{}

func (t *httpClient) Do(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", fmt.Sprintf("cilium/%s", version.Version))
	return http.DefaultClient.Do(req)
}

func constructTokenCredential(userAssignedIdentityID string) (azcore.TokenCredential, error) {
	if userAssignedIdentityID != "" {
		return azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{
			ID: azidentity.ClientID(userAssignedIdentityID),
		})
	} else {
		// Authorizer based on file first and then environment variables
		credential, err := azidentity.NewDefaultAzureCredential(nil) //TODO: does this read credentials from file?
		if err == nil {
			return credential, nil
		}
		return azidentity.NewEnvironmentCredential(nil)
	}
}

// NewClient returns a new Azure client
func NewClient(cloudName, subscriptionID, resourceGroup, userAssignedIdentityID string, metrics MetricsAPI, rateLimit float64, burst int, usePrimary bool) (*Client, error) {
	credential, err := constructTokenCredential(userAssignedIdentityID)
	if err != nil {
		return nil, err
	}

	//env, err := azure.EnvironmentFromName(cloudName)
	_, err = azure.EnvironmentFromName(cloudName)
	if err != nil {
		return nil, err
	}

	ClientOptions := arm.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			//Cloud: cloud.Configuration{
			//	ActiveDirectoryAuthorityHost: env.ActiveDirectoryEndpoint,
			//},
			Cloud:     cloud.AzurePublic,
			Transport: &httpClient{},
		},
	}

	interfacesClient, err := armnetwork.NewInterfacesClient(subscriptionID, credential, &ClientOptions)
	if err != nil {
		return nil, err
	}

	virtualnetworksClient, err := armnetwork.NewVirtualNetworksClient(subscriptionID, credential, &ClientOptions)
	if err != nil {
		return nil, err
	}

	vmssClient, err := armcompute.NewVirtualMachineScaleSetVMsClient(subscriptionID, credential, &ClientOptions)
	if err != nil {
		return nil, err
	}

	vmscalesetsClient, err := armcompute.NewVirtualMachineScaleSetsClient(subscriptionID, credential, &ClientOptions)
	if err != nil {
		return nil, err
	}

	c := &Client{
		resourceGroup:   resourceGroup,
		interfaces:      interfacesClient,
		virtualnetworks: virtualnetworksClient,
		vmss:            vmssClient,
		vmscalesets:     vmscalesetsClient,
		metricsAPI:      metrics,
		limiter:         helpers.NewAPILimiter(metrics, rateLimit, burst),
		usePrimary:      usePrimary,
	}

	return c, nil
}

// deriveStatus returns a status string
func deriveStatus(err error) string {
	if err != nil {
		return "Failed"
	}

	return "OK"
}

// describeNetworkInterfaces lists all Azure Interfaces in the client's resource group
func (c *Client) describeNetworkInterfaces(ctx context.Context) ([]armnetwork.Interface, error) {
	networkInterfaces, err := c.vmssNetworkInterfaces(ctx)
	if err != nil {
		return nil, err
	}

	vmInterfaces, err := c.vmNetworkInterfaces(ctx)
	if err != nil {
		return nil, err
	}

	return append(networkInterfaces, vmInterfaces...), nil
}

// vmNetworkInterfaces list all interfaces of non-VMSS instances in the client's resource group
func (c *Client) vmNetworkInterfaces(ctx context.Context) ([]armnetwork.Interface, error) {
	var networkInterfaces []armnetwork.Interface

	c.limiter.Limit(ctx, interfacesListComplete)
	sinceStart := spanstat.Start()

	var err error
	interfacesPager := c.interfaces.NewListPager(c.resourceGroup, nil)
	defer func() {
		c.metricsAPI.ObserveAPICall(interfacesListComplete, deriveStatus(err), sinceStart.Seconds())
	}()
	for interfacesPager.More() {
		nextResult, err := interfacesPager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, intf := range nextResult.Value {
			if intf.Name == nil {
				continue
			}
			networkInterfaces = append(networkInterfaces, *intf)
		}
	}

	return networkInterfaces, nil
}

// vmssNetworkInterfaces list all interfaces from VMS in Scale Sets in the client's resource group
func (c *Client) vmssNetworkInterfaces(ctx context.Context) ([]armnetwork.Interface, error) {
	var networkInterfaces []armnetwork.Interface

	c.limiter.Limit(ctx, virtualMachineScaleSetsListAll)
	sinceStart := spanstat.Start()

	var err error
	vmscalesetsPager := c.vmscalesets.NewListPager(c.resourceGroup, nil)
	defer func() {
		c.metricsAPI.ObserveAPICall(virtualMachineScaleSetsListAll, deriveStatus(err), sinceStart.Seconds())
	}()
	for vmscalesetsPager.More() {
		nextResult, err := vmscalesetsPager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, scaleset := range nextResult.Value {
			if scaleset.Name == nil {
				continue
			}

			c.limiter.Limit(ctx, interfacesListAll)
			sinceStart := spanstat.Start()
			var err2 error

			interfacesPager := c.interfaces.NewListVirtualMachineScaleSetNetworkInterfacesPager(c.resourceGroup, *scaleset.Name, nil)
			defer func() {
				c.metricsAPI.ObserveAPICall(interfacesListVirtualMachineScaleSetNetworkInterfacesComplete, deriveStatus(err2), sinceStart.Seconds())
			}()
			for interfacesPager.More() {
				nextResult, err2 := interfacesPager.NextPage(ctx)
				//if err2 != nil {
				//	// For scale set created by AKS node group (otherwise it will return an empty list) without any instances API will return not found. Then it can be skipped.
				//	var v autorest.DetailedError
				//	if errors.As(err2, &v) && v.StatusCode == http.StatusNotFound {
				//		continue
				//	}
				//	return nil, err2
				//}
				if err2 != nil {
					return nil, err2
				}
				for _, intf := range nextResult.Value {
					if intf.Name == nil {
						continue
					}
					networkInterfaces = append(networkInterfaces, *intf)
				}
			}
		}
	}

	return networkInterfaces, nil
}

// parseInterfaces parses a armnetwork.Interface as returned by the Azure API
// converts it into a types.AzureInterface
func parseInterface(iface *armnetwork.Interface, subnets ipamTypes.SubnetMap, usePrimary bool) (instanceID string, i *types.AzureInterface) {
	i = &types.AzureInterface{}

	if iface.Properties.VirtualMachine != nil && iface.Properties.VirtualMachine.ID != nil {
		instanceID = strings.ToLower(*iface.Properties.VirtualMachine.ID)
	}

	if iface.Properties.MacAddress != nil {
		// Azure API reports MAC addresses as AA-BB-CC-DD-EE-FF
		i.MAC = strings.ReplaceAll(*iface.Properties.MacAddress, "-", ":")
	}

	if iface.ID != nil {
		i.SetID(*iface.ID)
	}

	if iface.Name != nil {
		i.Name = *iface.Name
	}

	if iface.Properties.NetworkSecurityGroup != nil {
		if iface.Properties.NetworkSecurityGroup.ID != nil {
			i.SecurityGroup = *iface.Properties.NetworkSecurityGroup.ID
		}
	}

	if iface.Properties.IPConfigurations != nil {
		for _, ip := range (*iface).Properties.IPConfigurations {
			if !usePrimary && ip.Properties.Primary != nil && *ip.Properties.Primary {
				continue
			}
			if ip.Properties.PrivateIPAddress != nil {
				addr := types.AzureAddress{
					IP:    *ip.Properties.PrivateIPAddress,
					State: strings.ToLower(string(*ip.Properties.ProvisioningState)),
				}

				if ip.Properties.Subnet != nil {
					addr.Subnet = *ip.Properties.Subnet.ID
					if subnet, ok := subnets[addr.Subnet]; ok {
						if subnet.CIDR != nil {
							i.CIDR = subnet.CIDR.String()
						}
						if gateway := deriveGatewayIP(subnet.CIDR.IP); gateway != "" {
							i.GatewayIP = gateway
							i.Gateway = gateway
						}
					}
				}

				i.Addresses = append(i.Addresses, addr)
			}
		}
	}

	return
}

// deriveGatewayIP finds the default gateway for a given Azure subnet.
// inspired by pkg/ipam/crd.go (as AWS, Azure reserves the first subnet IP for the gw).
// Ref: https://docs.microsoft.com/en-us/azure/virtual-network/virtual-networks-faq#are-there-any-restrictions-on-using-ip-addresses-within-these-subnets
func deriveGatewayIP(subnetIP net.IP) string {
	addr := subnetIP.To4()
	return net.IPv4(addr[0], addr[1], addr[2], addr[3]+1).String()
}

// GetInstances returns the list of all instances including all attached
// interfaces as instanceMap
func (c *Client) GetInstances(ctx context.Context, subnets ipamTypes.SubnetMap) (*ipamTypes.InstanceMap, error) {
	instances := ipamTypes.NewInstanceMap()

	networkInterfaces, err := c.describeNetworkInterfaces(ctx)
	if err != nil {
		return nil, err
	}

	for _, iface := range networkInterfaces {
		if id, azureInterface := parseInterface(&iface, subnets, c.usePrimary); id != "" {
			instances.Update(id, ipamTypes.InterfaceRevision{Resource: azureInterface})
		}
	}

	return instances, nil
}

// describeVpcs lists all VPCs
func (c *Client) describeVpcs(ctx context.Context) ([]armnetwork.VirtualNetwork, error) {
	var vpcs []armnetwork.VirtualNetwork
	var err error

	c.limiter.Limit(ctx, virtualNetworksList)
	sinceStart := spanstat.Start()
	virtualnetworksPager := c.virtualnetworks.NewListAllPager(nil) //note: not listing just in c.resourcegroup
	defer func() {
		c.metricsAPI.ObserveAPICall(virtualnetworksListAll, deriveStatus(err), sinceStart.Seconds())
	}()
	for virtualnetworksPager.More() {
		nextResult, err := virtualnetworksPager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, vpc := range nextResult.Value {
			vpcs = append(vpcs, *vpc)
		}
	}

	return vpcs, nil
}

func parseSubnet(subnet *armnetwork.Subnet) (s *ipamTypes.Subnet) {
	s = &ipamTypes.Subnet{ID: *subnet.ID}
	if subnet.Name != nil {
		s.Name = *subnet.Name
	}

	if subnet.Properties.AddressPrefix != nil {
		c, err := cidr.ParseCIDR(*subnet.Properties.AddressPrefix)
		if err != nil {
			return nil
		}
		s.CIDR = c
		if subnet.Properties.IPConfigurations != nil {
			s.AvailableAddresses = c.AvailableIPs() - len(subnet.Properties.IPConfigurations)
		}
	}

	return
}

// GetVpcsAndSubnets retrieves and returns all Vpcs
func (c *Client) GetVpcsAndSubnets(ctx context.Context) (ipamTypes.VirtualNetworkMap, ipamTypes.SubnetMap, error) {
	vpcs := ipamTypes.VirtualNetworkMap{}
	subnets := ipamTypes.SubnetMap{}

	vpcList, err := c.describeVpcs(ctx)
	if err != nil {
		return nil, nil, err
	}

	for _, v := range vpcList {
		if v.ID == nil {
			continue
		}

		vpc := &ipamTypes.VirtualNetwork{ID: *v.ID}
		vpcs[vpc.ID] = vpc

		if v.Properties.Subnets != nil {
			for _, subnet := range v.Properties.Subnets {
				if subnet.ID == nil {
					continue
				}
				if s := parseSubnet(subnet); s != nil {
					subnets[*subnet.ID] = s
				}
			}
		}
	}

	return vpcs, subnets, nil
}

func generateIpConfigName() string {
	return "Cilium-" + rand.String(8)
}

// AssignPrivateIpAddressesVMSS assign a private IP to an interface attached to a VMSS instance
func (c *Client) AssignPrivateIpAddressesVMSS(ctx context.Context, instanceID, vmssName, subnetID, interfaceName string, addresses int) error {
	var netIfConfig *armcompute.VirtualMachineScaleSetNetworkConfiguration

	c.limiter.Limit(ctx, virtualMachineScaleSetVMsGet)
	sinceStart := spanstat.Start()
	result, err := c.vmss.Get(ctx, c.resourceGroup, vmssName, instanceID, nil)
	c.metricsAPI.ObserveAPICall(virtualMachineScaleSetVMsGet, deriveStatus(err), sinceStart.Seconds())
	if err != nil {
		return fmt.Errorf("failed to get VM %s from VMSS %s: %w", instanceID, vmssName, err)
	}

	// Search for the existing network interface configuration
	if result.Properties.NetworkProfileConfiguration != nil {
		for _, networkInterfaceConfiguration := range result.Properties.NetworkProfileConfiguration.NetworkInterfaceConfigurations {
			if networkInterfaceConfiguration.Name != nil && *networkInterfaceConfiguration.Name == interfaceName {
				netIfConfig = networkInterfaceConfiguration
				break
			}
		}
	}

	if netIfConfig == nil {
		return fmt.Errorf("interface %s does not exist in VM %s", interfaceName, instanceID)
	}

	// All IPConfigurations on the NIC should reference the same set of Application Security Groups (ASGs).
	// So we should first fetch the set of ASGs referenced by other IPConfigurations so that it can be
	// added to the new IPConfigurations.
	var appSecurityGroups []*armcompute.SubResource
	if ipConfigs := netIfConfig.Properties.IPConfigurations; len(ipConfigs) > 0 {
		appSecurityGroups = ipConfigs[0].Properties.ApplicationSecurityGroups
	}

	ipConfigurations := make([]*armcompute.VirtualMachineScaleSetIPConfiguration, 0, addresses)
	for i := 0; i < addresses; i++ {
		ipConfigurations = append(ipConfigurations,
			&armcompute.VirtualMachineScaleSetIPConfiguration{
				Name: to.Ptr(generateIpConfigName()),
				Properties: &armcompute.VirtualMachineScaleSetIPConfigurationProperties{
					ApplicationSecurityGroups: appSecurityGroups,
					PrivateIPAddressVersion:   to.Ptr(armcompute.IPVersionIPv4),
					Subnet:                    &armcompute.APIEntityReference{ID: to.Ptr(subnetID)},
				},
			},
		)
	}

	ipConfigurations = append(netIfConfig.Properties.IPConfigurations, ipConfigurations...)
	netIfConfig.Properties.IPConfigurations = ipConfigurations

	// Unset imageReference, because if this contains a reference to an image from the
	// Azure Compute Gallery, including this reference in an update to the VMSS instance
	// will cause a permissions error, because the reference includes an Azure-managed
	// subscription ID.
	// Removing the image reference indicates to the API that we don't want to change it.
	// See https://github.com/Azure/AKS/issues/1819.
	if result.Properties.StorageProfile != nil {
		result.Properties.StorageProfile.ImageReference = nil
	}

	c.limiter.Limit(ctx, virtualMachineScaleSetVMsUpdate)
	sinceStart = spanstat.Start()
	poller, err := c.vmss.BeginUpdate(ctx, c.resourceGroup, vmssName, instanceID, result.VirtualMachineScaleSetVM, nil)
	defer func() {
		c.metricsAPI.ObserveAPICall(virtualMachineScaleSetVMsUpdate, deriveStatus(err), sinceStart.Seconds())
	}()
	if err != nil {
		return fmt.Errorf("unable to update virtualmachinescaleset: %w", err)
	}

	if _, err := poller.PollUntilDone(ctx, nil); err != nil {
		return fmt.Errorf("error while waiting for virtualmachinescalesets Update to complete: %w", err)
	}

	return nil
}

// AssignPrivateIpAddressesVM assign a private IP to an interface attached to a standalone instance
func (c *Client) AssignPrivateIpAddressesVM(ctx context.Context, subnetID, interfaceName string, addresses int) error {
	c.limiter.Limit(ctx, interfacesGet)
	sinceStart := spanstat.Start()
	iface, err := c.interfaces.Get(ctx, c.resourceGroup, interfaceName, nil)
	c.metricsAPI.ObserveAPICall(interfacesGet, deriveStatus(err), sinceStart.Seconds())
	if err != nil {
		return fmt.Errorf("failed to get standalone instance's interface %s: %w", interfaceName, err)
	}

	// All IPConfigurations on the NIC should reference the same set of Application Security Groups (ASGs).
	// So we should first fetch the set of ASGs referenced by other IPConfigurations so that it can be
	// added to the new IPConfigurations.
	var appSecurityGroups []*armnetwork.ApplicationSecurityGroup
	if ipConfigs := iface.Properties.IPConfigurations; len(ipConfigs) > 0 {
		appSecurityGroups = ipConfigs[0].Properties.ApplicationSecurityGroups
	}

	ipConfigurations := make([]*armnetwork.InterfaceIPConfiguration, 0, addresses)
	for i := 0; i < addresses; i++ {
		ipConfigurations = append(ipConfigurations, &armnetwork.InterfaceIPConfiguration{
			Name: to.Ptr(generateIpConfigName()),
			Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
				ApplicationSecurityGroups: appSecurityGroups,
				PrivateIPAllocationMethod: to.Ptr(armnetwork.IPAllocationMethodDynamic),
				Subnet: &armnetwork.Subnet{
					ID: to.Ptr(subnetID),
				},
			},
		})
	}

	ipConfigurations = append(iface.Properties.IPConfigurations, ipConfigurations...)
	iface.Properties.IPConfigurations = ipConfigurations

	c.limiter.Limit(ctx, interfacesCreateOrUpdate)
	sinceStart = spanstat.Start()
	poller, err := c.interfaces.BeginCreateOrUpdate(ctx, c.resourceGroup, interfaceName, iface.Interface, nil)
	defer func() {
		c.metricsAPI.ObserveAPICall(interfacesCreateOrUpdate, deriveStatus(err), sinceStart.Seconds())
	}()
	if err != nil {
		return fmt.Errorf("unable to update interface %s: %w", interfaceName, err)
	}

	if _, err := poller.PollUntilDone(ctx, nil); err != nil {
		return fmt.Errorf("error while waiting for interface CreateOrUpdate to complete for %s: %w", interfaceName, err)
	}

	return nil
}
