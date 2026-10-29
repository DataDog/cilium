// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net/netip"
	"slices"

	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/mac"
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

	StateUpdating = "updating"

	// PrefixLengthIPv4 is the length of the IPv4 prefixes assigned to
	// interfaces
	PrefixLengthIPv4 = 28

	// PrefixSizeIPv4 is the number of addresses in an IPv4 prefix
	PrefixSizeIPv4 = 1 << (32 - PrefixLengthIPv4)
)

// AzureSpec is the Azure specification of a node running via the Azure IPAM
//
// The Azure specification can either be provided explicitly by the user or the
// cilium agent running on the node can be instructed to create the CiliumNode
// custom resource along with an Azure specification when the node registers
// itself to the Kubernetes cluster.
// This struct is embedded into v2.CiliumNode
type AzureSpec struct {
	// InterfaceName is the name of the interface the cilium-operator
	// will use to allocate all the IPs on
	//
	// +kubebuilder:validation:Optional
	InterfaceName string `json:"interface-name,omitempty"`

	// DisablePrefixDelegation determines whether the operator may assign IP
	// prefixes to the node's interfaces. It is set by agents that can use
	// prefixes; the operator assigns none to nodes where it is unset.
	//
	// +kubebuilder:validation:Optional
	DisablePrefixDelegation *bool `json:"disable-prefix-delegation,omitempty"`
}

// AzureStatus is the status of Azure addressing of the node.
// This struct is embedded into v2.CiliumNode
type AzureStatus struct {
	// Interfaces is the list of interfaces on the node
	//
	// +optional
	Interfaces []AzureInterface `json:"interfaces,omitempty"`
}

// AzureAddress is an IP address assigned to an AzureInterface
type AzureAddress struct {
	// IP is the ip address of the address
	//
	// +optional
	IP iputil.Addr `json:"ip,omitzero"`

	// State is the provisioning state of the address
	State string `json:"state,omitempty"`
}

// AzurePrefix is an IP prefix assigned to an AzureInterface
type AzurePrefix struct {
	// CIDR is the IP prefix of a secondary IP configuration
	//
	// +optional
	CIDR iputil.Prefix `json:"cidr,omitzero"`

	// State is the provisioning state of the IP configuration
	//
	// +optional
	State string `json:"state,omitempty"`
}

// AzureSubnet describes the subnet an AzureInterface is attached to. Azure
// enforces one subnet per NIC, so it is tracked once per interface (mirroring
// the AWS and Alibaba patterns).
type AzureSubnet struct {
	// ID is the resource ID of the subnet
	//
	// +optional
	ID string `json:"id,omitempty"`

	// CIDR is the CIDR range associated with the subnet
	//
	// +optional
	CIDR iputil.Prefix `json:"cidr,omitzero"`
}

// Every field must be exported and JSON-serialized; see
// TestAzureStatusHasNoUnserializedState. Kept out of the doc comment so it
// stays out of the generated CRD description.

// AzureInterface represents an Azure Interface
type AzureInterface struct {
	// ID is the identifier
	//
	// +optional
	ID string `json:"id,omitempty"`

	// IP is the primary IP of the interface
	//
	// +optional
	IP iputil.Addr `json:"ip,omitzero"`

	// Name is the name of the interface
	//
	// +optional
	Name string `json:"name,omitempty"`

	// MAC is the mac address
	//
	// +optional
	MAC mac.MAC `json:"mac,omitzero"`

	// State is the provisioning state
	//
	// +optional
	State string `json:"state,omitempty"`

	// Addresses is the list of secondary IPs associated with the interface.
	// The primary IP is tracked separately in the IP field, but is also
	// included here when the operator is configured to expose it for
	// allocation.
	//
	// +optional
	Addresses []AzureAddress `json:"addresses,omitempty"`

	// Prefixes is the list of IP prefixes associated with the interface
	//
	// +optional
	Prefixes []AzurePrefix `json:"prefixes,omitempty"`

	// SecurityGroup is the security group associated with the interface
	SecurityGroup string `json:"security-group,omitempty"`

	// Subnet is the subnet the interface is attached to.
	//
	// +optional
	Subnet AzureSubnet `json:"subnet,omitzero"`

	// Gateway is the interface's subnet's default route
	//
	// +optional
	Gateway iputil.Addr `json:"gateway"`
}

// UsablePrefixes returns the succeeded IPv4 prefixes of the interface.
func (a *AzureInterface) UsablePrefixes() []netip.Prefix {
	var prefixes []netip.Prefix
	for _, prefix := range a.Prefixes {
		if prefix.State != StateSucceeded || !prefix.CIDR.IsValid() || !prefix.CIDR.Addr().Is4() {
			continue
		}
		prefixes = append(prefixes, prefix.CIDR.Prefix)
	}
	return prefixes
}

// PoolCIDRs returns the CIDRs the agent serves from: succeeded secondary
// addresses as host prefixes and succeeded prefixes.
func (s *AzureStatus) PoolCIDRs() []iputil.Prefix {
	var cidrs []iputil.Prefix
	for _, iface := range s.Interfaces {
		for _, address := range iface.Addresses {
			if address.State != StateSucceeded || !address.IP.IsValid() {
				continue
			}
			prefix := netip.PrefixFrom(address.IP.Addr, address.IP.BitLen())
			cidrs = append(cidrs, iputil.PrefixFrom(prefix))
		}
		for _, prefix := range iface.UsablePrefixes() {
			cidrs = append(cidrs, iputil.PrefixFrom(prefix))
		}
	}

	slices.SortFunc(cidrs, func(a, b iputil.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	return cidrs
}

func (a *AzureInterface) DeepCopyInterface() types.Interface {
	return a.DeepCopy()
}

// InterfaceID returns the identifier of the interface
func (a *AzureInterface) InterfaceID() string {
	return a.ID
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
