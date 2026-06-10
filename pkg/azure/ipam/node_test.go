// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/azure/types"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
)

func TestGetMaximumAllocatableIPv4(t *testing.T) {
	n := &Node{}
	require.Equal(t, types.InterfaceAddressLimit, n.GetMaximumAllocatable(ipamTypes.IPv4))
}
