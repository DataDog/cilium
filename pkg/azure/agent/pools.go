// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ipam"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

var poolAccessor = ipam.PoolSpecAccessors{
	FromResource: func(node *ciliumv2.CiliumNode) ipamTypes.IPAMPoolSpec {
		pools := ipamTypes.IPAMPoolSpec{
			Requested: node.Spec.IPAM.Pools.Requested,
			Allocated: node.Spec.IPAM.Pools.Allocated,
		}

		if len(node.Status.Azure.Interfaces) == 0 {
			return pools
		}

		pools.Allocated = []ipamTypes.IPAMPoolAllocation{
			{
				Pool:         defaults.IPAMDefaultIPPool,
				AllowFirstIP: true,
				AllowLastIP:  true,
				CIDRs:        node.Status.Azure.PoolCIDRs(),
			},
		}

		return pools
	},
	Authoritative: func(node *ciliumv2.CiliumNode) bool {
		return len(node.Status.Azure.Interfaces) > 0
	},
	ToResource: func(node *ciliumv2.CiliumNode, spec ipamTypes.IPAMPoolSpec) bool {
		if !node.Spec.IPAM.Pools.DeepEqual(&spec) {
			node.Spec.IPAM.Pools = spec
			return true
		}
		return false
	},
}
