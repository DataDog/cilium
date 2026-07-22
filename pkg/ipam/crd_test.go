// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	azureTypes "github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/cidr"
	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/ipmasq"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/trigger"
)

func TestIPNotAvailableInPoolError(t *testing.T) {
	err := NewIPNotAvailableInPoolError(net.ParseIP("1.1.1.1"))
	err2 := NewIPNotAvailableInPoolError(net.ParseIP("1.1.1.1"))
	assert.Equal(t, err, err2)
	assert.ErrorIs(t, err, err2)

	err = NewIPNotAvailableInPoolError(net.ParseIP("2.1.1.1"))
	err2 = NewIPNotAvailableInPoolError(net.ParseIP("1.1.1.1"))
	assert.NotEqual(t, err, err2)
	assert.NotErrorIs(t, err, err2)

	err = NewIPNotAvailableInPoolError(net.ParseIP("2.1.1.1"))
	err2 = errors.New("another error")
	assert.NotEqual(t, err, err2)
	assert.NotErrorIs(t, err, err2)

	err = errors.New("another error")
	err2 = NewIPNotAvailableInPoolError(net.ParseIP("2.1.1.1"))
	assert.NotEqual(t, err, err2)
	assert.NotErrorIs(t, err, err2)

	err = NewIPNotAvailableInPoolError(net.ParseIP("1.1.1.1"))
	err2 = nil
	assert.NotErrorIs(t, err, err2)

	err = nil
	err2 = NewIPNotAvailableInPoolError(net.ParseIP("1.1.1.1"))
	assert.NotErrorIs(t, err, err2)

	// We don't match against strings. It must be the sentinel value.
	err = errors.New("IP 2.1.1.1 is not available")
	err2 = NewIPNotAvailableInPoolError(net.ParseIP("2.1.1.1"))
	assert.NotEqual(t, err, err2)
	assert.NotErrorIs(t, err, err2)
}

func testDaemonConfig() *option.DaemonConfig {
	return &option.DaemonConfig{
		EnableIPv4:              true,
		EnableIPv6:              false,
		EnableHealthChecking:    true,
		EnableUnreachableRoutes: false,
		IPAM:                    ipamOption.IPAMCRD,
	}
}

func newFakeNodeStore(conf *option.DaemonConfig, t *testing.T) *nodeStore {
	tr, err := trigger.NewTrigger(trigger.Parameters{
		Name:        "fake-crd-allocator-node-refresher",
		MinInterval: 3 * time.Second,
		TriggerFunc: func(reasons []string) {},
	})
	if err != nil {
		logging.Fatal(hivetest.Logger(t), "Unable to initialize CiliumNode synchronization trigger", logfields.Error, err)
	}
	store := &nodeStore{
		allocators:         []*crdAllocator{},
		allocationPoolSize: map[Family]int{},
		conf:               conf,
		refreshTrigger:     tr,
	}
	return store
}

func TestMarkForReleaseNoAllocate(t *testing.T) {
	cn := newCiliumNode("node1", 4, 4, 0)
	dummyResource := ipamTypes.AllocationIP{Resource: "foo"}
	for i := 1; i <= 4; i++ {
		cn.Spec.IPAM.Pool[fmt.Sprintf("1.1.1.%d", i)] = dummyResource
	}

	fakeAddressing := fakeTypes.NewNodeAddressing()
	conf := testDaemonConfig()
	initNodeStore.Do(func() {}) // Ensure the real initNodeStore is not called
	sharedNodeStore = newFakeNodeStore(conf, t)
	sharedNodeStore.ownNode = cn

	localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
	ipam := NewIPAM(NewIPAMParams{
		Logger:         hivetest.Logger(t),
		NodeAddressing: fakeAddressing,
		AgentConfig:    conf,
		NodeDiscovery:  &ownerMock{},
		LocalNodeStore: localNodeStore,
		K8sEventReg:    &ownerMock{},
		NodeResource:   &resourceMock{},
		MTUConfig:      &mtuMock,
	})
	ipam.ConfigureAllocator()
	sharedNodeStore.updateLocalNodeResource(cn)

	// Allocate the first 3 IPs
	for i := 1; i <= 3; i++ {
		epipv4 := netip.MustParseAddr(fmt.Sprintf("1.1.1.%d", i))
		_, err := ipam.ipv4Allocator.Allocate(epipv4.AsSlice(), fmt.Sprintf("test%d", i), PoolDefault())
		require.NoError(t, err)
	}

	// Update 1.1.1.4 as marked for release like operator would.
	cn.Status.IPAM.ReleaseIPs["1.1.1.4"] = ipamOption.IPAMMarkForRelease
	// Attempts to allocate 1.1.1.4 should fail, since it's already marked for release
	epipv4 := netip.MustParseAddr("1.1.1.4")
	_, err := ipam.ipv4Allocator.Allocate(epipv4.AsSlice(), "test", PoolDefault())
	require.Error(t, err)
	// Call agent's CRD update function. status for 1.1.1.4 should change from marked for release to ready for release
	sharedNodeStore.updateLocalNodeResource(cn)
	require.Equal(t, ipamOption.IPAMReadyForRelease, string(cn.Status.IPAM.ReleaseIPs["1.1.1.4"]))

	// Verify that 1.1.1.3 is denied for release, since it's already in use
	cn.Status.IPAM.ReleaseIPs["1.1.1.3"] = ipamOption.IPAMMarkForRelease
	sharedNodeStore.updateLocalNodeResource(cn)
	require.Equal(t, ipamOption.IPAMDoNotRelease, string(cn.Status.IPAM.ReleaseIPs["1.1.1.3"]))
}

func TestNodeStoreStaticIPStatus(t *testing.T) {
	newNode := func(tags map[string]string, assigned string) *ciliumv2.CiliumNode {
		cn := newCiliumNode("node1", 0, 0, 0)
		cn.Spec.IPAM.StaticIPTags = tags
		cn.Status.IPAM.AssignedStaticIP = assigned
		return cn
	}

	tests := []struct {
		name                  string
		ownNode               *ciliumv2.CiliumNode
		wantRequestedStaticIP bool
		wantAssignedStaticIP  string
	}{
		{
			name:                  "nil node",
			ownNode:               nil,
			wantRequestedStaticIP: false,
			wantAssignedStaticIP:  "",
		},
		{
			name:                  "no static IP requested",
			ownNode:               newNode(nil, ""),
			wantRequestedStaticIP: false,
			wantAssignedStaticIP:  "",
		},
		{
			name:                  "static IP requested but not yet assigned",
			ownNode:               newNode(map[string]string{"env": "prod"}, ""),
			wantRequestedStaticIP: true,
			wantAssignedStaticIP:  "",
		},
		{
			name:                  "static IP requested and assigned",
			ownNode:               newNode(map[string]string{"env": "prod"}, "1.2.3.4"),
			wantRequestedStaticIP: true,
			wantAssignedStaticIP:  "1.2.3.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &nodeStore{ownNode: tt.ownNode}
			requested, assigned := store.staticIPStatus()
			assert.Equal(t, tt.wantRequestedStaticIP, requested)
			assert.Equal(t, tt.wantAssignedStaticIP, assigned)
		})
	}
}

type ipMasqMapDummy struct{}

func (m ipMasqMapDummy) Update(netip.Prefix) error { return nil }

func (m ipMasqMapDummy) Delete(netip.Prefix) error { return nil }

func (m ipMasqMapDummy) Dump() ([]netip.Prefix, error) { return []netip.Prefix{}, nil }

func TestIPMasq(t *testing.T) {
	cn := newCiliumNode("node1", 4, 4, 0)
	dummyResource := ipamTypes.AllocationIP{Resource: "eni-1"}
	cn.Spec.IPAM.Pool["10.1.1.226"] = dummyResource
	cn.Status.ENI.ENIs = map[string]eniTypes.ENI{
		"eni-1": {
			ID: "eni-1",
			Addresses: []string{
				"10.1.1.226",
				"10.1.1.229",
			},
			VPC: eniTypes.AwsVPC{
				ID:          "vpc-1",
				PrimaryCIDR: "10.1.0.0/16",
				CIDRs: []string{
					"10.2.0.0/16",
				},
			},
		},
	}

	fakeAddressing := fakeTypes.NewNodeAddressing()
	conf := testDaemonConfig()
	conf.IPAM = ipamOption.IPAMENI
	conf.EnableIPMasqAgent = true
	ipMasqAgent := ipmasq.NewIPMasqAgent(hivetest.Logger(t), "", ipMasqMapDummy{})
	err := ipMasqAgent.Start()
	require.NoError(t, err)

	initNodeStore.Do(func() {}) // Ensure the real initNodeStore is not called
	sharedNodeStore = newFakeNodeStore(conf, t)
	sharedNodeStore.ownNode = cn

	localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
	ipam := NewIPAM(NewIPAMParams{
		Logger:         hivetest.Logger(t),
		NodeAddressing: fakeAddressing,
		AgentConfig:    conf,
		NodeDiscovery:  &ownerMock{},
		LocalNodeStore: localNodeStore,
		K8sEventReg:    &ownerMock{},
		NodeResource:   &resourceMock{},
		MTUConfig:      &mtuMock,
		IPMasqAgent:    ipMasqAgent,
	})
	ipam.ConfigureAllocator()

	epipv4 := netip.MustParseAddr("10.1.1.226")
	result, err := ipam.ipv4Allocator.Allocate(epipv4.AsSlice(), "test1", PoolDefault())
	require.NoError(t, err)
	// The resulting CIDRs should contain the VPC CIDRs and the default ip-masq-agent CIDRs from pkg/ipmasq/ipmasq.go
	require.ElementsMatch(
		t,
		[]string{
			// VPC CIDRs
			"10.1.0.0/16",
			"10.2.0.0/16",
			// Default ip-masq-agent CIDRs
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"100.64.0.0/10",
			"192.0.0.0/24",
			"192.0.2.0/24",
			"192.88.99.0/24",
			"198.18.0.0/15",
			"198.51.100.0/24",
			"203.0.113.0/24",
			"240.0.0.0/4",
			"169.254.0.0/16",
		},
		result.CIDRs,
	)

	ipMasqAgent.Stop()
}

func TestAzureIPMasq(t *testing.T) {
	cn := newCiliumNode("node1", 4, 4, 0)
	dummyResource := ipamTypes.AllocationIP{Resource: "azure-interface-1"}
	cn.Spec.IPAM.Pool["10.10.1.5"] = dummyResource
	cn.Status.Azure.Interfaces = []azureTypes.AzureInterface{
		{
			ID:      "azure-interface-1",
			Name:    "eth0",
			MAC:     "00:00:5e:00:53:01",
			Gateway: "10.10.1.1",
			CIDR:    "10.10.1.0/24",
			Addresses: []azureTypes.AzureAddress{
				{IP: "10.10.1.5", Subnet: "subnet-1", State: azureTypes.StateSucceeded},
			},
		},
	}

	fakeAddressing := fakeTypes.NewNodeAddressing()
	conf := testDaemonConfig()
	conf.IPAM = ipamOption.IPAMAzure
	conf.EnableIPMasqAgent = true
	ipMasqAgent := ipmasq.NewIPMasqAgent(hivetest.Logger(t), "", ipMasqMapDummy{})
	err := ipMasqAgent.Start()
	require.NoError(t, err)

	initNodeStore.Do(func() {}) // Ensure the real initNodeStore is not called
	sharedNodeStore = newFakeNodeStore(conf, t)
	sharedNodeStore.ownNode = cn

	localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
	ipam := NewIPAM(NewIPAMParams{
		Logger:         hivetest.Logger(t),
		NodeAddressing: fakeAddressing,
		AgentConfig:    conf,
		NodeDiscovery:  &ownerMock{},
		LocalNodeStore: localNodeStore,
		K8sEventReg:    &ownerMock{},
		NodeResource:   &resourceMock{},
		MTUConfig:      &mtuMock,
		IPMasqAgent:    ipMasqAgent,
	})
	ipam.ConfigureAllocator()

	epipv4 := netip.MustParseAddr("10.10.1.5")
	result, err := ipam.ipv4Allocator.Allocate(epipv4.AsSlice(), "test1", PoolDefault())
	require.NoError(t, err)
	// The resulting CIDRs should contain the Azure interface CIDR and the default ip-masq-agent CIDRs
	require.ElementsMatch(
		t,
		[]string{
			// Azure interface CIDR
			"10.10.1.0/24",
			// Default ip-masq-agent CIDRs
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"100.64.0.0/10",
			"192.0.0.0/24",
			"192.0.2.0/24",
			"192.88.99.0/24",
			"198.18.0.0/15",
			"198.51.100.0/24",
			"203.0.113.0/24",
			"240.0.0.0/4",
			"169.254.0.0/16",
		},
		result.CIDRs,
	)

	ipMasqAgent.Stop()
}

// TestDeriveVpcCIDRsAzure covers the primary-CIDR selection criterion for
// Azure nodes: when Spec.Azure.InterfaceName pins the node to a specific
// interface, that interface's CIDR must be selected regardless of slice
// order; otherwise selection must be permutation-invariant (deterministic
// regardless of Status.Azure.Interfaces ordering), unparseable CIDRs must
// be skipped rather than aborting selection, and an empty/all-unparseable
// interface list must fall through cleanly without panicking.
func TestDeriveVpcCIDRsAzure(t *testing.T) {
	logger := hivetest.Logger(t)

	mkIfaces := func(order []int) []azureTypes.AzureInterface {
		all := map[int]azureTypes.AzureInterface{
			0: {ID: "intf-b", Name: "eth1", CIDR: "10.0.10.0/24"},
			1: {ID: "intf-a", Name: "eth0", CIDR: "10.0.9.0/24"},
			2: {ID: "intf-c", Name: "eth2", CIDR: "bogus-cidr"},
		}
		out := make([]azureTypes.AzureInterface, 0, len(order))
		for _, i := range order {
			out = append(out, all[i])
		}
		return out
	}

	t.Run("permutation invariant without configured interface name", func(t *testing.T) {
		orderings := [][]int{{0, 1, 2}, {1, 0, 2}, {2, 0, 1}, {2, 1, 0}}
		var want *cidr.CIDR
		for i, order := range orderings {
			cn := &ciliumv2.CiliumNode{}
			cn.Status.Azure.Interfaces = mkIfaces(order)
			got, secondary := deriveVpcCIDRs(logger, cn)
			require.NotNil(t, got, "ordering %v", order)
			require.Empty(t, secondary)
			if i == 0 {
				want = got
			} else {
				require.Equal(t, want.String(), got.String(), "ordering %v selected a different primary CIDR than ordering %v", order, orderings[0])
			}
		}
		// The deterministic winner must be one of the parseable CIDRs.
		require.Contains(t, []string{"10.0.9.0/24", "10.0.10.0/24"}, want.String())
	})

	t.Run("configured interface name takes precedence over determinism criterion", func(t *testing.T) {
		cn := &ciliumv2.CiliumNode{}
		cn.Spec.Azure.InterfaceName = "eth1"
		cn.Status.Azure.Interfaces = mkIfaces([]int{1, 0, 2})
		got, _ := deriveVpcCIDRs(logger, cn)
		require.NotNil(t, got)
		require.Equal(t, "10.0.10.0/24", got.String())
	})

	t.Run("configured interface name not found falls back to deterministic selection", func(t *testing.T) {
		cn := &ciliumv2.CiliumNode{}
		cn.Spec.Azure.InterfaceName = "eth99" // does not exist in mkIfaces
		cn.Status.Azure.Interfaces = mkIfaces([]int{1, 0, 2})
		got, secondary := deriveVpcCIDRs(logger, cn)
		require.NotNil(t, got)
		require.Empty(t, secondary)
		require.Equal(t, "10.0.9.0/24", got.String()) // intf-a, lexicographically smallest ID
	})

	t.Run("configured interface name matches but has unparseable CIDR falls back to deterministic selection", func(t *testing.T) {
		cn := &ciliumv2.CiliumNode{}
		cn.Spec.Azure.InterfaceName = "eth2" // intf-c, CIDR is "bogus-cidr"
		cn.Status.Azure.Interfaces = mkIfaces([]int{1, 0, 2})
		got, secondary := deriveVpcCIDRs(logger, cn)
		require.NotNil(t, got)
		require.Empty(t, secondary)
		require.Equal(t, "10.0.9.0/24", got.String()) // intf-a, lexicographically smallest ID
	})

	t.Run("configured interface name set but no interfaces have a parseable CIDR returns nil", func(t *testing.T) {
		cn := &ciliumv2.CiliumNode{}
		cn.Spec.Azure.InterfaceName = "eth1"
		cn.Status.Azure.Interfaces = []azureTypes.AzureInterface{
			{ID: "intf-1", Name: "eth1", CIDR: "not-a-cidr"},
		}
		got, secondary := deriveVpcCIDRs(logger, cn)
		require.Nil(t, got)
		require.Empty(t, secondary)
	})

	t.Run("all unparseable CIDRs falls through without panicking", func(t *testing.T) {
		cn := &ciliumv2.CiliumNode{}
		cn.Status.Azure.Interfaces = []azureTypes.AzureInterface{
			{ID: "intf-1", CIDR: "not-a-cidr"},
			{ID: "intf-2", CIDR: ""},
		}
		got, secondary := deriveVpcCIDRs(logger, cn)
		require.Nil(t, got)
		require.Empty(t, secondary)
	})

	t.Run("empty interfaces slice falls through cleanly", func(t *testing.T) {
		cn := &ciliumv2.CiliumNode{}
		got, secondary := deriveVpcCIDRs(logger, cn)
		require.Nil(t, got)
		require.Empty(t, secondary)
	})

	t.Run("pool spanning multiple interfaces returns all backing CIDRs, ignoring InterfaceName pin", func(t *testing.T) {
		// intf-a and intf-c both back live pool allocations; intf-b does
		// not and must not be selected even though it would otherwise win
		// the lexicographic-ID tie-break, and even though InterfaceName is
		// pinned to it.
		cn := &ciliumv2.CiliumNode{}
		cn.Spec.Azure.InterfaceName = "eth1"                  // intf-b, not in the pool
		cn.Status.Azure.Interfaces = mkIfaces([]int{0, 1, 2}) // intf-b, intf-a, intf-c(bogus)
		cn.Spec.IPAM.Pool = ipamTypes.AllocationMap{
			"10.0.9.4":  {Resource: "intf-a"},
			"10.0.9.5":  {Resource: "intf-a"},
			"10.0.11.4": {Resource: "intf-d"},
		}
		cn.Status.Azure.Interfaces = append(cn.Status.Azure.Interfaces, azureTypes.AzureInterface{
			ID: "intf-d", Name: "eth3", CIDR: "10.0.11.0/24",
		})

		got, secondary := deriveVpcCIDRs(logger, cn)
		require.NotNil(t, got)
		require.Equal(t, "10.0.9.0/24", got.String(), "primary must be the lowest-ID interface actually backing the pool")
		require.Len(t, secondary, 1)
		require.Equal(t, "10.0.11.0/24", secondary[0].String())
	})

	t.Run("pool referencing an interface without a parseable CIDR is skipped but other pool interfaces are still returned", func(t *testing.T) {
		cn := &ciliumv2.CiliumNode{}
		cn.Status.Azure.Interfaces = mkIfaces([]int{0, 1, 2}) // intf-b, intf-a, intf-c(bogus)
		cn.Spec.IPAM.Pool = ipamTypes.AllocationMap{
			"10.0.9.4": {Resource: "intf-a"},
			"10.0.x.4": {Resource: "intf-c"}, // intf-c's CIDR is unparseable
		}

		got, secondary := deriveVpcCIDRs(logger, cn)
		require.NotNil(t, got)
		require.Equal(t, "10.0.9.0/24", got.String())
		require.Empty(t, secondary)
	})

	t.Run("pool referencing an interface not present in status falls through to auto-selected CIDR", func(t *testing.T) {
		cn := &ciliumv2.CiliumNode{}
		cn.Status.Azure.Interfaces = mkIfaces([]int{1, 0, 2})
		cn.Spec.IPAM.Pool = ipamTypes.AllocationMap{
			"10.0.99.4": {Resource: "intf-not-attached"},
		}

		got, secondary := deriveVpcCIDRs(logger, cn)
		require.NotNil(t, got)
		require.Empty(t, secondary)
		require.Equal(t, "10.0.9.0/24", got.String(), "intf-a, lexicographically smallest ID fallback since the pool does not resolve to any attached interface")
	})
}

func Test_validateENIConfig(t *testing.T) {
	type args struct {
		node *ciliumv2.CiliumNode
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		want    string
	}{
		{
			name: "Consistent ENI config",
			args: args{
				node: &ciliumv2.CiliumNode{
					Spec: ciliumv2.NodeSpec{
						IPAM: ipamTypes.IPAMSpec{
							Pool: ipamTypes.AllocationMap{
								"10.1.1.226": ipamTypes.AllocationIP{
									Resource: "eni-1",
								},
							},
						},
					},
					Status: ciliumv2.NodeStatus{
						ENI: eniTypes.ENIStatus{
							ENIs: map[string]eniTypes.ENI{
								"eni-1": {
									ID: "eni-1",
									Addresses: []string{
										"10.1.1.226",
										"10.1.1.229",
									},
									VPC: eniTypes.AwsVPC{
										ID:          "vpc-1",
										PrimaryCIDR: "10.1.0.0/16",
										CIDRs: []string{
											"10.1.0.0/16",
											"10.2.0.0/16",
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Missing VPC Primary CIDR",
			args: args{
				node: &ciliumv2.CiliumNode{
					Spec: ciliumv2.NodeSpec{
						IPAM: ipamTypes.IPAMSpec{
							Pool: ipamTypes.AllocationMap{
								"10.1.1.226": ipamTypes.AllocationIP{
									Resource: "eni-1",
								},
							},
						},
					},
					Status: ciliumv2.NodeStatus{
						ENI: eniTypes.ENIStatus{
							ENIs: map[string]eniTypes.ENI{
								"eni-1": {
									ID: "eni-1",
									Addresses: []string{
										"10.1.1.226",
										"10.1.1.229",
									},
									VPC: eniTypes.AwsVPC{
										ID: "vpc-1",
									},
								},
							},
						},
					},
				},
			},
			wantErr: true,
			want:    "VPC Primary CIDR not set for ENI eni-1",
		},
		{
			name: "VPC CIDRs contain invalid value",
			args: args{
				node: &ciliumv2.CiliumNode{
					Spec: ciliumv2.NodeSpec{
						IPAM: ipamTypes.IPAMSpec{
							Pool: ipamTypes.AllocationMap{
								"10.1.1.226": ipamTypes.AllocationIP{
									Resource: "eni-1",
								},
							},
						},
					},
					Status: ciliumv2.NodeStatus{
						ENI: eniTypes.ENIStatus{
							ENIs: map[string]eniTypes.ENI{
								"eni-1": {
									ID: "eni-1",
									Addresses: []string{
										"10.1.1.226",
										"10.1.1.229",
									},
									VPC: eniTypes.AwsVPC{
										ID:          "vpc-1",
										PrimaryCIDR: "10.1.0.0/16",
										CIDRs: []string{
											"",
										},
									},
								},
							},
						},
					},
				},
			},
			wantErr: true,
			want:    "VPC CIDR not set for ENI eni-1",
		},
		{
			name: "ENI not found in status",
			args: args{
				node: &ciliumv2.CiliumNode{
					Spec: ciliumv2.NodeSpec{
						IPAM: ipamTypes.IPAMSpec{
							Pool: ipamTypes.AllocationMap{
								"10.1.1.226": ipamTypes.AllocationIP{
									Resource: "eni-1",
								},
							},
						},
					},
					Status: ciliumv2.NodeStatus{
						ENI: eniTypes.ENIStatus{
							ENIs: map[string]eniTypes.ENI{
								"eni-2": {
									ID: "eni-2",
									Addresses: []string{
										"10.1.1.226",
										"10.1.1.229",
									},
									VPC: eniTypes.AwsVPC{
										ID:          "vpc-1",
										PrimaryCIDR: "10.1.0.0/16",
										CIDRs: []string{
											"10.1.0.0/16",
											"10.2.0.0/16",
										},
									},
								},
							},
						},
					},
				},
			},
			wantErr: true,
			want:    "ENI eni-1 not found in status",
		},
		{
			name: "ENI IP not found in status",
			args: args{
				node: &ciliumv2.CiliumNode{
					Spec: ciliumv2.NodeSpec{
						IPAM: ipamTypes.IPAMSpec{
							Pool: ipamTypes.AllocationMap{
								"10.1.1.227": ipamTypes.AllocationIP{
									Resource: "eni-1",
								},
							},
						},
					},
					Status: ciliumv2.NodeStatus{
						ENI: eniTypes.ENIStatus{
							ENIs: map[string]eniTypes.ENI{
								"eni-1": {
									ID: "eni-1",
									Addresses: []string{
										"10.1.1.226",
										"10.1.1.229",
									},
									VPC: eniTypes.AwsVPC{
										ID:          "vpc-1",
										PrimaryCIDR: "10.1.0.0/16",
										CIDRs: []string{
											"10.1.0.0/16",
											"10.2.0.0/16",
										},
									},
								},
							},
						},
					},
				},
			},
			wantErr: true,
			want:    "ENI eni-1 does not have address 10.1.1.227",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateENIConfig(tt.args.node)
			require.Equal(t, tt.wantErr, got != nil, "error: %v", got)
			if tt.wantErr {
				require.Equal(t, tt.want, got.Error())
			}
		})
	}
}
