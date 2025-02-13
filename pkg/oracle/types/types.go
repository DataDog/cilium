// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"github.com/cilium/cilium/pkg/ipam/types"
)

const (
	// TODO remove this?
	// ProviderPrefix is the prefix used to indicate that a k8s ProviderID
	// represents an Oracle resource
	ProviderPrefix = "ocid1."

	// InterfaceAddressLimit is the maximum number of IP addresses on an interface.
	// A VNIC has a primary IP and up to 63 secondary IPs.
	// https://docs.oracle.com/en-us/iaas/Content/Network/Tasks/managingIPaddresses.htm#overview__about_secondary
	InterfaceAddressLimit = 64
)

// OracleSpec is the Oracle specification of a node running via the Oracle IPAM
//
// The Oracle specification can either be provided explicitly by the user or the
// Cilium Agent running on the node can be instructed to create the CiliumNode
// custom resource along with an Oracle specification when the node registers
// itself to the Kubernetes cluster.
// This struct is embedded into v2.CiliumNode
type OracleSpec struct {

	// +kubebuilder:validation:Optional
	AvailabilityDomain string `json:"availability-domain,omitempty"`

	// Tags used to find the subnet where the VNICs should be created
	//
	// +kubebuilder:validation:Optional
	SubnetTags map[string]string `json:"subnet-tags,omitempty"`

	// +kubebuilder:validation:Optional
	SecurityGroupIds []string `json:"security-group-ids,omitempty"`

	// +kubebuilder:validation:Optional
	InstanceShape string `json:"instance-shape,omitempty"`

	// Note: this information can be retrieved from the API as well but
	// getting it from IMDS is more reliable for Flex Shapes
	// +kubebuilder:validation:Optional
	MaxVnicAttachments int `json:"max-vnic-attachments,omitempty"`
}

// OracleStatus is the status of Oracle addressing of the node.
// This struct is embedded into v2.CiliumNode
type OracleStatus struct {
	// Interfaces is the list of interfaces on the node
	//
	// +kubebuilder:validation:Optional
	Interfaces []OracleInterface `json:"interfaces,omitempty"`
}

// OracleInterface represents an Oracle VNIC
type OracleInterface struct {
	// ID is the VNIC ID
	//
	// +kubebuilder:validation:Optional
	ID string `json:"id,omitempty"`

	// +kubebuilder:validation:Optional
	IsPrimary bool `json:"is-primary,omitempty"`

	// +kubebuilder:validation:Optional
	IP string `json:"ip,omitempty"`

	// +kubebuilder:validation:Optional
	SecondaryIPs []OracleIP `json:"secondary-ips,omitempty"`

	// +kubebuilder:validation:Optional
	MAC string `json:"mac,omitempty"`

	// +kubebuilder:validation:Optional
	InstanceID string `json:"instance-id,omitempty"`

	// +kubebuilder:validation:Optional
	VCN OracleVCN `json:"vcn,omitempty"`

	// +kubebuilder:validation:Optional
	SubnetID string `json:"subnet-id,omitempty"`

	// +kubebuilder:validation:Optional
	SubnetCIDR string `json:"subnet-cidr,omitempty"`

	// +kubebuilder:validation:Optional
	AvailabilityDomain string `json:"availability-domain,omitempty"`

	// +kubebuilder:validation:Optional
	SecurityGroupIds []string `json:"security-group-ids,omitempty"`
}

type OracleVCN struct {
	// +kubebuilder:validation:Optional
	PrimaryCIDR string `json:"primary-cidr,omitempty"`

	// +kubebuilder:validation:Optional
	SecondaryCIDRs []string `json:"secondary-cidrs,omitempty"`
}

type OracleIP struct {
	// The OCID of the PrivateIP object. Required for the DeletePrivateIp operation.
	// +kubebuilder:validation:Optional
	ID string `json:"id,omitempty"`

	// +kubebuilder:validation:Optional
	IP string `json:"ip,omitempty"`
}

func (a *OracleInterface) DeepCopyInterface() types.Interface {
	// TODO
	return nil
}

// SetID sets the Oracle interface ID, as well as extracting other fields from
// the ID itself.
func (a *OracleInterface) SetID(id string) {
	a.ID = id
}

// InterfaceID returns the identifier of the interface
func (a *OracleInterface) InterfaceID() string {
	return a.ID
}

// ForeachAddress iterates over all addresses and calls fn
func (a *OracleInterface) ForeachAddress(id string, fn types.AddressIterator) error {
	for _, ip := range a.SecondaryIPs {
		if err := fn(id, a.ID, ip.IP, a.SubnetID, ip); err != nil {
			return err
		}
	}

	return nil
}

func (a *OracleInterface) IsMaximumIPCapacityReached() bool {
	return len(a.SecondaryIPs)+1 == InterfaceAddressLimit
}
