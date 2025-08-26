// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package limits

import (
	"testing"

	ec2_types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	ec2mock "github.com/cilium/cilium/pkg/aws/ec2/mock"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
)

var api *ec2mock.API

func TestGet(t *testing.T) {
	api = ec2mock.NewAPI(nil, nil, nil, nil)
	api.UpdateInstanceTypes([]ec2_types.InstanceTypeInfo{{
		InstanceType: "test.large",
		NetworkInfo: &ec2_types.NetworkInfo{
			MaximumNetworkInterfaces:  ptr.To[int32](4),
			Ipv4AddressesPerInterface: ptr.To[int32](5),
			Ipv6AddressesPerInterface: ptr.To[int32](6),
		},
		Hypervisor: ec2_types.InstanceTypeHypervisorNitro,
		BareMetal:  ptr.To(false),
	}})
	newLimitsGetter, err := NewLimitsGetter(hivetest.Logger(t), api)
	require.NoError(t, err)

	// Test 1: Get unknown instance type
	limit, err := newLimitsGetter.Get(t.Context(), "unknown")
	require.Error(t, err)
	require.Equal(t, ipamTypes.Limits{}, limit)
	// Test 2: Get Known instance type
	limit, err = newLimitsGetter.Get(t.Context(), "test.large")
	require.NoError(t, err)
	require.Equal(t, ipamTypes.Limits{
		Adapters:       4,
		IPv4:           5,
		IPv6:           6,
		HypervisorType: "nitro",
		IsBareMetal:    false,
	}, limit)

	// Test 3: EC2 API call and update limits but trigger can't be triggered
	api.UpdateInstanceTypes([]ec2_types.InstanceTypeInfo{{
		InstanceType: "newtype",
		NetworkInfo: &ec2_types.NetworkInfo{
			MaximumNetworkInterfaces:  ptr.To[int32](4),
			Ipv4AddressesPerInterface: ptr.To[int32](15),
			Ipv6AddressesPerInterface: ptr.To[int32](15),
		},
		Hypervisor: ec2_types.InstanceTypeHypervisorNitro,
		BareMetal:  ptr.To(false),
	}})

	// Test 3: Get the newly added instance type (should work immediately since it's now in the mock API)
	limit, err = newLimitsGetter.Get(t.Context(), "newtype")
	require.NoError(t, err)
	require.Equal(t, ipamTypes.Limits{
		Adapters:       4,
		IPv4:           15,
		IPv6:           15,
		HypervisorType: "nitro",
		IsBareMetal:    false,
	}, limit)
}

func TestInitEC2APIUpdateTrigger(t *testing.T) {
	// Setup mock API with some test instance types
	api := ec2mock.NewAPI(nil, nil, nil, nil)
	api.UpdateInstanceTypes([]ec2_types.InstanceTypeInfo{
		{
			InstanceType: "test.large",
			NetworkInfo: &ec2_types.NetworkInfo{
				MaximumNetworkInterfaces:  ptr.To[int32](4),
				Ipv4AddressesPerInterface: ptr.To[int32](10),
				Ipv6AddressesPerInterface: ptr.To[int32](10),
			},
			Hypervisor: ec2_types.InstanceTypeHypervisorNitro,
			BareMetal:  ptr.To(false),
		},
	})

	// Create a new LimitsGetter instance
	limitsGetter, err := NewLimitsGetter(hivetest.Logger(t), api)
	require.NotNil(t, limitsGetter)
	require.NoError(t, err)

	// Verify that the limits were actually retrieved
	limits, err := limitsGetter.Get(t.Context(), "test.large")
	require.NoError(t, err)
	require.Equal(t, ipamTypes.Limits{
		Adapters:       4,
		IPv4:           10,
		IPv6:           10,
		HypervisorType: "nitro",
		IsBareMetal:    false,
	}, limits)
}
