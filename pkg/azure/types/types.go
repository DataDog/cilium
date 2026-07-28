// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"

	"github.com/cilium/cilium/pkg/ipam/types"
)

const (
	// ProviderPrefix is the prefix used to indicate that a k8s ProviderID
	// represents an Azure resource
	ProviderPrefix = "azure://"

	// InterfaceAddressLimit is the maximum number of addresses on an interface
	//
	//
	// For more information:
	// https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits?toc=%2fazure%2fvirtual-network%2ftoc.json#networking-limits
	InterfaceAddressLimit = 256

	// StateSucceeded is the address state for a successfully provisioned address
	StateSucceeded = "succeeded"

	// Resource type names for Azure resources
	resourceTypeVirtualMachines         = "virtualMachines"
	resourceTypeVirtualMachineScaleSets = "virtualMachineScaleSets"
)

// AzureSpec is the Azure specification of a node running via the Azure IPAM
//
// The Azure specification can either be provided explicitly by the user or the
// cilium agent running on the node can be instructed to create the CiliumNode
// custom resource along with an Azure specification when the node registers
// itself to the Kubernetes cluster.
// This struct is embedded into v2.CiliumNode
//
// +k8s:deepcopy-gen=true
type AzureSpec struct {
	// InterfaceName is the name of the interface the cilium-operator
	// will use to allocate all the IPs on
	//
	// +kubebuilder:validation:Optional
	InterfaceName string `json:"interface-name,omitempty"`
}

// AzureStatus is the status of Azure addressing of the node.
// This struct is embedded into v2.CiliumNode
//
// +k8s:deepcopy-gen=true
type AzureStatus struct {
	// Interfaces is the list of interfaces on the node
	//
	// +optional
	Interfaces []AzureInterface `json:"interfaces,omitempty"`
}

// AzureAddress is an IP address assigned to an AzureInterface
type AzureAddress struct {
	// IP is the ip address of the address
	IP string `json:"ip,omitempty"`

	// Subnet is the subnet the address belongs to
	Subnet string `json:"subnet,omitempty"`

	// State is the provisioning state of the address
	State string `json:"state,omitempty"`
}

// AzureInterface represents an Azure Interface
//
// Every field must be exported and JSON-serialized; see
// TestAzureStatusHasNoUnserializedState.
//
// +k8s:deepcopy-gen=true
type AzureInterface struct {
	// ID is the identifier
	//
	// +optional
	ID string `json:"id,omitempty"`

	// Name is the name of the interface
	//
	// +optional
	Name string `json:"name,omitempty"`

	// MAC is the mac address
	//
	// +optional
	MAC string `json:"mac,omitempty"`

	// State is the provisioning state
	//
	// +optional
	State string `json:"state,omitempty"`

	// Addresses is the list of all IPs associated with the interface,
	// including all secondary addresses
	//
	// +optional
	Addresses []AzureAddress `json:"addresses,omitempty"`

	// SecurityGroup is the security group associated with the interface
	SecurityGroup string `json:"security-group,omitempty"`

	// GatewayIP is the interface's subnet's default route
	//
	// OBSOLETE: This field is obsolete, please use Gateway field instead.
	//
	// +optional
	GatewayIP string `json:"GatewayIP"`

	// Gateway is the interface's subnet's default route
	//
	// +optional
	Gateway string `json:"gateway"`

	// CIDR is the range that the interface belongs to.
	//
	// +optional
	CIDR string `json:"cidr,omitempty"`
}

func (a *AzureInterface) DeepCopyInterface() types.Interface {
	return a.DeepCopy()
}

// InterfaceID returns the identifier of the interface
func (a *AzureInterface) InterfaceID() string {
	return a.ID
}

// parseAzureResourceID extracts the resource group name, VMSS name, and VM ID
// from a network interface Azure resource ID. Missing or unparseable components
// yield empty strings.
func parseAzureResourceID(id string) (resourceGroup, vmssName, vmID string) {
	resourceID, err := arm.ParseResourceID(id)
	if err != nil {
		return "", "", ""
	}

	resourceGroup = resourceID.ResourceGroupName

	// For VMSS instances, walk up the parent chain to extract VMSS name and VM ID
	// Resource ID structure for VMSS VM interfaces:
	// /subscriptions/xxx/resourceGroups/yyy/providers/Microsoft.Compute/virtualMachineScaleSets/ssss/virtualMachines/vvv/networkInterfaces/iii
	current := resourceID
	for current != nil {
		resourceType := current.ResourceType
		if len(resourceType.Types) == 0 {
			current = current.Parent
			continue
		}

		lastType := resourceType.Types[len(resourceType.Types)-1]

		if strings.EqualFold(lastType, resourceTypeVirtualMachines) {
			vmID = current.Name
		}

		if strings.EqualFold(lastType, resourceTypeVirtualMachineScaleSets) {
			vmssName = current.Name
		}

		current = current.Parent
	}

	return resourceGroup, vmssName, vmID
}

// GetResourceGroup returns the resource group the interface belongs to
func (a *AzureInterface) GetResourceGroup() string {
	resourceGroup, _, _ := parseAzureResourceID(a.ID)
	return resourceGroup
}

// GetVMScaleSetName returns the VM scale set name the interface belongs to
func (a *AzureInterface) GetVMScaleSetName() string {
	_, vmssName, _ := parseAzureResourceID(a.ID)
	return vmssName
}

// GetVMID returns the VM ID the interface belongs to
func (a *AzureInterface) GetVMID() string {
	_, _, vmID := parseAzureResourceID(a.ID)
	return vmID
}

// ForeachAddress iterates over all addresses and calls fn
func (a *AzureInterface) ForeachAddress(id string, fn types.AddressIterator) error {
	for _, address := range a.Addresses {
		if err := fn(id, a.ID, address.IP, address.Subnet, address); err != nil {
			return err
		}
	}

	return nil
}
