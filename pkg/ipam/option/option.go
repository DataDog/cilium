// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

const (
	// IPAMKubernetes is the value to select the Kubernetes PodCIDR based
	// hostscope IPAM mode
	IPAMKubernetes = "kubernetes"

	// IPAMCRD is the value to select the CRD-backed IPAM plugin for
	// option.IPAM
	IPAMCRD = "crd"

	// IPAMENI is the value to select the AWS ENI IPAM plugin for option.IPAM
	IPAMENI = "eni"

	// IPAMAzure is the value to select the Azure IPAM plugin for
	// option.IPAM
	IPAMAzure = "azure"

	// IPAMClusterPool is the value to select the cluster pool mode for
	// option.IPAM
	IPAMClusterPool = "cluster-pool"

	// IPAMMultiPool is the value to select the multi pool IPAM mode
	IPAMMultiPool = "multi-pool"

	// IPAMAlibabaCloud is the value to select the AlibabaCloud ENI IPAM plugin for option.IPAM
	IPAMAlibabaCloud = "alibabacloud"

	// IPAMDelegatedPlugin is the value to select CNI delegated IPAM plugin mode.
	// In this mode, Cilium CNI invokes another CNI binary (the delegated plugin) for IPAM.
	// See https://www.cni.dev/docs/spec/#section-4-plugin-delegation
	IPAMDelegatedPlugin = "delegated-plugin"
)

const (
	IPAMMarkForRelease  = "marked-for-release"
	IPAMReadyForRelease = "ready-for-release"
	IPAMDoNotRelease    = "do-not-release"
	IPAMReleased        = "released"
)

// ENIPDBlockSizeIPv4 is the number of IPs available on an ENI IPv4 prefix. Currently, AWS only supports /28 fixed size
// prefixes. Every /28 prefix contains 16 IP addresses.
// See https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-prefix-eni.html#ec2-prefix-basics for more details
const ENIPDBlockSizeIPv4 = 16

// ENIIPv6PrefixLength is the prefix length of an ENI IPv6 prefix. AWS assigns
// fixed /80 IPv6 prefixes via prefix delegation.
//
// Unlike IPv4 (see ENIPDBlockSizeIPv4), there is no IP-count "block size" for
// IPv6: a /80 holds 2^48 addresses, far too many to enumerate or to use as a
// capacity multiplier. IPv6 prefix delegation is only supported in multi-pool
// mode, where the operator hands the whole /80 to the node as a pod CIDR and
// the agent manages individual addresses within it. Capacity is therefore
// accounted in prefixes/CIDRs, not in individual IPs.
// See https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-prefix-eni.html#ec2-prefix-basics for more details
const ENIIPv6PrefixLength = 80
