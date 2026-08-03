// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eni

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/defaults"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/nodediscovery"
)

func TestSeedPoolRequest(t *testing.T) {
	for _, tc := range []struct {
		name        string
		preAllocate int
		requested   []ipamTypes.IPAMPoolRequest
		in          nodediscovery.ENIMutateInputs
		want        []ipamTypes.IPAMPoolRequest
	}{
		{
			name:        "IPv6-only agent requests no IPv4 address",
			preAllocate: 1,
			in:          nodediscovery.ENIMutateInputs{EnableIPv6: true},
			want: []ipamTypes.IPAMPoolRequest{
				{
					Pool:   defaults.IPAMDefaultIPPool,
					Needed: ipamTypes.IPAMPoolDemand{IPv4Addrs: 0, IPv6Addrs: 1},
				},
			},
		},
		{
			name:        "IPv4-only agent requests no IPv6 address",
			preAllocate: 4,
			in:          nodediscovery.ENIMutateInputs{EnableIPv4: true},
			want: []ipamTypes.IPAMPoolRequest{
				{
					Pool:   defaults.IPAMDefaultIPPool,
					Needed: ipamTypes.IPAMPoolDemand{IPv4Addrs: 4, IPv6Addrs: 0},
				},
			},
		},
		{
			name:        "dual stack agent requests both families",
			preAllocate: 2,
			in:          nodediscovery.ENIMutateInputs{EnableIPv4: true, EnableIPv6: true},
			want: []ipamTypes.IPAMPoolRequest{
				{
					Pool:   defaults.IPAMDefaultIPPool,
					Needed: ipamTypes.IPAMPoolDemand{IPv4Addrs: 2, IPv6Addrs: 2},
				},
			},
		},
		{
			name: "pre-allocate defaults to the IPAM default",
			in:   nodediscovery.ENIMutateInputs{EnableIPv4: true},
			want: []ipamTypes.IPAMPoolRequest{
				{
					Pool:   defaults.IPAMDefaultIPPool,
					Needed: ipamTypes.IPAMPoolDemand{IPv4Addrs: defaults.IPAMPreAllocation},
				},
			},
		},
		{
			name:        "existing demand of the IPAM layer is preserved",
			preAllocate: 1,
			requested: []ipamTypes.IPAMPoolRequest{
				{
					Pool:   defaults.IPAMDefaultIPPool,
					Needed: ipamTypes.IPAMPoolDemand{IPv6Addrs: 12},
				},
			},
			in: nodediscovery.ENIMutateInputs{EnableIPv4: true, EnableIPv6: true},
			want: []ipamTypes.IPAMPoolRequest{
				{
					Pool:   defaults.IPAMDefaultIPPool,
					Needed: ipamTypes.IPAMPoolDemand{IPv6Addrs: 12},
				},
			},
		},
		{
			name:        "no family enabled seeds nothing",
			preAllocate: 1,
			in:          nodediscovery.ENIMutateInputs{},
			want:        nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cn := &ciliumv2.CiliumNode{}
			cn.Spec.IPAM.PreAllocate = tc.preAllocate
			cn.Spec.IPAM.Pools.Requested = tc.requested

			seedPoolRequest(cn, tc.in)

			require.Equal(t, tc.want, cn.Spec.IPAM.Pools.Requested)
		})
	}
}
