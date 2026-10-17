// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"net/netip"

	azureTypes "github.com/cilium/cilium/pkg/azure/types"
)

func azureInterfaceCIDR(iface azureTypes.AzureInterface) netip.Prefix {
	if iface.Subnet.CIDR.IsValid() {
		return iface.Subnet.CIDR.Prefix
	}
	return iface.CIDR.Prefix //nolint:staticcheck // compatibility with operators predating Subnet.CIDR
}
