// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
	"github.com/cilium/cilium/pkg/time"
)

// NodeAddress is an IP address assigned to a network interface on a Cilium node
// that is considered a "host" IP address.
type NodeAddress struct {
	Addr netip.Addr

	// NodePort is true if this address is to be used for NodePort.
	// If --nodeport-addresses is set, then all addresses on native
	// devices that are contained within the specified CIDRs are chosen.
	// If it is not set, then only the primary IPv4 and/or IPv6 address
	// of each native device is used.
	NodePort bool

	// Primary is true if this is the primary IPv4 or IPv6 address of this device.
	// This is mainly used to pick the address for BPF masquerading.
	Primary bool

	// DeviceName is the name of the network device from which this address
	// is derived from.
	DeviceName string
}

func (n *NodeAddress) IP() net.IP {
	return n.Addr.AsSlice()
}

func (n *NodeAddress) String() string {
	return fmt.Sprintf("%s (%s)", n.Addr, n.DeviceName)
}

func (n NodeAddress) TableHeader() []string {
	return []string{
		"Address",
		"NodePort",
		"Primary",
		"DeviceName",
	}
}

func (n NodeAddress) TableRow() []string {
	return []string{
		n.Addr.String(),
		fmt.Sprintf("%v", n.NodePort),
		fmt.Sprintf("%v", n.Primary),
		n.DeviceName,
	}
}

type NodeAddressConfig struct {
	NodePortAddresses []*cidr.CIDR `mapstructure:"nodeport-addresses"`
}

var (
	// NodeAddressIndex is the primary index for node addresses:
	//
	//   var nodeAddresses Table[NodeAddress]
	//   nodeAddresses.First(txn, NodeAddressIndex.Query(netip.MustParseAddr("1.2.3.4")))
	NodeAddressIndex = statedb.Index[NodeAddress, netip.Addr]{
		Name: "id",
		FromObject: func(a NodeAddress) index.KeySet {
			return index.NewKeySet(index.NetIPAddr(a.Addr))
		},
		FromKey: index.NetIPAddr,
		Unique:  true,
	}

	NodeAddressDeviceNameIndex = statedb.Index[NodeAddress, string]{
		Name: "name",
		FromObject: func(a NodeAddress) index.KeySet {
			return index.NewKeySet(index.String(a.DeviceName))
		},
		FromKey: index.String,
		Unique:  false,
	}

	NodeAddressTableName statedb.TableName = "node-addresses"

	// NodeAddressCell provides Table[NodeAddress] and a background controller
	// that derives the node addresses from the low-level Table[*Device].
	//
	// The Table[NodeAddress] contains the actual assigned addresses on the node,
	// but not for example external Kubernetes node addresses that may be merely
	// NATd to a private address. Those can be queried through [node.LocalNodeStore].
	NodeAddressCell = cell.Module(
		"node-address",
		"Table of node addresses derived from system network devices",

		cell.ProvidePrivate(NewNodeAddressTable),
		cell.Provide(
			newNodeAddressController,
			newAddressScopeMax,
		),
		cell.Config(NodeAddressConfig{}),
	)
)

func NewNodeAddressTable() (statedb.RWTable[NodeAddress], error) {
	return statedb.NewTable[NodeAddress](
		NodeAddressTableName,
		NodeAddressIndex,
		NodeAddressDeviceNameIndex,
	)
}

const (
	nodeAddressControllerMinInterval = 100 * time.Millisecond
)

// AddressScopeMax sets the maximum scope an IP address can have. A scope
// is defined in rtnetlink(7) as the distance to the destination where a
// lower number signifies a wider scope with RT_SCOPE_UNIVERSE (0) being
// the widest. Definitions in Go are in unix package, e.g.
// unix.RT_SCOPE_UNIVERSE and so on.
//
// This defaults to RT_SCOPE_LINK-1 (defaults.AddressScopeMax) and can be
// set by the user with --local-max-addr-scope.
type AddressScopeMax uint8

func newAddressScopeMax(cfg NodeAddressConfig, daemonCfg *option.DaemonConfig) (AddressScopeMax, error) {
	return AddressScopeMax(daemonCfg.AddressScopeMax), nil
}

func (cfg NodeAddressConfig) getNets() []*net.IPNet {
	nets := make([]*net.IPNet, len(cfg.NodePortAddresses))
	for i, cidr := range cfg.NodePortAddresses {
		nets[i] = cidr.IPNet
	}
	return nets
}

func (NodeAddressConfig) Flags(flags *pflag.FlagSet) {
	flags.StringSlice(
		"nodeport-addresses",
		nil,
		"A whitelist of CIDRs to limit which IPs are used for NodePort. If not set, primary IPv4 and/or IPv6 address of each native device is used.")
}

type nodeAddressControllerParams struct {
	cell.In

	HealthScope     cell.Scope
	Log             logrus.FieldLogger
	Config          NodeAddressConfig
	Lifecycle       cell.Lifecycle
	Jobs            job.Registry
	DB              *statedb.DB
	Devices         statedb.Table[*Device]
	NodeAddresses   statedb.RWTable[NodeAddress]
	AddressScopeMax AddressScopeMax
}

type nodeAddressController struct {
	nodeAddressControllerParams

	tracker *statedb.DeleteTracker[*Device]
}

// newNodeAddressController constructs the node address controller & registers its
// lifecycle hooks and then provides Table[NodeAddress] to the application.
// This enforces proper ordering, e.g. controller is started before anything
// that depends on Table[NodeAddress] and allows it to populate it before
// it is accessed.
func newNodeAddressController(p nodeAddressControllerParams) (tbl statedb.Table[NodeAddress], err error) {
	if err := p.DB.RegisterTable(p.NodeAddresses); err != nil {
		return nil, err
	}

	n := nodeAddressController{nodeAddressControllerParams: p}
	n.register()
	return n.NodeAddresses, nil
}

func (n *nodeAddressController) register() {
	g := n.Jobs.NewGroup(n.HealthScope)
	g.Add(job.OneShot("node-address-update", n.run))

	n.Lifecycle.Append(
		cell.Hook{
			OnStart: func(ctx cell.HookContext) error {
				txn := n.DB.WriteTxn(n.NodeAddresses, n.Devices /* for delete tracker */)
				defer txn.Abort()

				// Start tracking deletions of devices.
				var err error
				n.tracker, err = n.Devices.DeleteTracker(txn, "node-addresses")
				if err != nil {
					return fmt.Errorf("DeleteTracker: %w", err)
				}

				// Do an immediate update to populate the table before it is read from.
				devices, _ := n.Devices.All(txn)
				for dev, _, ok := devices.Next(); ok; dev, _, ok = devices.Next() {
					n.update(txn, nil, n.getAddressesFromDevice(dev), nil, dev.Name)
				}
				txn.Commit()

				// Start the job in the background to incremental refresh
				// the node addresses.
				return g.Start(ctx)
			},
			OnStop: g.Stop,
		})

}

func (n *nodeAddressController) run(ctx context.Context, reporter cell.HealthReporter) error {
	defer n.tracker.Close()

	limiter := rate.NewLimiter(nodeAddressControllerMinInterval, 1)
	revision := statedb.Revision(0)
	for {
		txn := n.DB.WriteTxn(n.NodeAddresses)
		process := func(dev *Device, deleted bool, rev statedb.Revision) error {
			// Note: prefix match! existing may contain node addresses from devices with names
			// prefixed by dev. See https://github.com/cilium/cilium/issues/29324.
			addrIter, _ := n.NodeAddresses.Get(txn, NodeAddressDeviceNameIndex.Query(dev.Name))
			existing := statedb.CollectSet[NodeAddress](addrIter)
			var new sets.Set[NodeAddress]
			if !deleted {
				new = n.getAddressesFromDevice(dev)
			}
			n.update(txn, existing, new, reporter, dev.Name)
			return nil
		}
		var watch <-chan struct{}
		revision, watch, _ = n.tracker.Process(txn, revision, process)
		txn.Commit()

		select {
		case <-ctx.Done():
			return nil
		case <-watch:
		}
		if err := limiter.Wait(ctx); err != nil {
			return err
		}
	}
}

// updates the node addresses of a single device.
func (n *nodeAddressController) update(txn statedb.WriteTxn, existing, new sets.Set[NodeAddress], reporter cell.HealthReporter, device string) {
	updated := false
	prefixLen := len(device)

	// Insert new addresses that did not exist.
	for addr := range new {
		if !existing.Has(addr) {
			updated = true
			n.NodeAddresses.Insert(txn, addr)
		}
	}

	// Remove addresses that were not part of the new set.
	for addr := range existing {
		// Ensure full device name match. 'device' may be a prefix of DeviceName, and we don't want
		// to delete node addresses of `cilium_host` because they are not on `cilium`.
		if prefixLen != len(addr.DeviceName) {
			continue
		}

		if !new.Has(addr) {
			updated = true
			n.NodeAddresses.Delete(txn, addr)
		}
	}

	if updated {
		addrs := showAddresses(new)
		n.Log.WithFields(logrus.Fields{"node-addresses": addrs, logfields.Device: device}).Info("Node addresses updated")
		if reporter != nil {
			reporter.OK(addrs)
		}
	}
}

func (n *nodeAddressController) getAddressesFromDevice(dev *Device) sets.Set[NodeAddress] {
	if dev.Flags&net.FlagUp == 0 {
		return nil
	}

	if dev.Name != defaults.HostDevice {
		// Skip obviously uninteresting devices. We include the HostDevice as its IP addresses are
		// considered node addresses and added to e.g. ipcache as HOST_IDs.
		for _, prefix := range defaults.ExcludedDevicePrefixes {
			if strings.HasPrefix(dev.Name, prefix) {
				return nil
			}
		}
	}

	addrs := make([]NodeAddress, 0, len(dev.Addrs))

	// ipv4Found and ipv6Found are set to true when the primary address is picked
	// (used for the Primary flag)
	ipv4Found, ipv6Found := false, false

	// The indexes for the first public and private addresses for picking NodePort
	// addresses.
	ipv4PublicIndex, ipv4PrivateIndex := -1, -1
	ipv6PublicIndex, ipv6PrivateIndex := -1, -1

	// Do a first pass to pick the addresses.
	for i, addr := range SortedAddresses(dev.Addrs) {
		// We keep the scope-based address filtering as was introduced
		// in 080857bdedca67d58ec39f8f96c5f38b22f6dc0b.
		skip := addr.Scope > uint8(n.AddressScopeMax) || addr.Addr.IsLoopback()

		// Always include LINK scope'd addresses for cilium_host device, regardless
		// of what the maximum scope is.
		skip = skip && !(dev.Name == defaults.HostDevice && addr.Scope == unix.RT_SCOPE_LINK)

		if skip {
			continue
		}

		isPublic := ip.IsPublicAddr(addr.Addr.AsSlice())
		primary := false
		if addr.Addr.Is4() {
			if !ipv4Found {
				ipv4Found = true
				primary = true
			}
			if ipv4PublicIndex < 0 && isPublic {
				ipv4PublicIndex = i
			}
			if ipv4PrivateIndex < 0 && !isPublic {
				ipv4PrivateIndex = i
			}
		}

		if addr.Addr.Is6() {
			if !ipv6Found {
				ipv6Found = true
				primary = true
			}

			if ipv6PublicIndex < 0 && isPublic {
				ipv6PublicIndex = i
			}
			if ipv6PrivateIndex < 0 && !isPublic {
				ipv6PrivateIndex = i
			}
		}

		// If the user has specified --nodeport-addresses use the addresses within the range for
		// NodePort. If not, the first private (or public if private not found) will be picked
		// by the logic following this loop.
		nodePort := false
		if len(n.Config.NodePortAddresses) > 0 {
			nodePort = dev.Selected && ip.NetsContainsAny(n.Config.getNets(), []*net.IPNet{ip.IPToPrefix(addr.AsIP())})
		}
		addrs = append(addrs,
			NodeAddress{
				Addr:       addr.Addr,
				Primary:    primary,
				NodePort:   nodePort,
				DeviceName: dev.Name,
			})
	}

	if len(n.Config.NodePortAddresses) == 0 {
		// Pick the NodePort addresses. Prefer private addresses if possible.
		if ipv4PrivateIndex >= 0 {
			addrs[ipv4PrivateIndex].NodePort = dev.Selected
		} else if ipv4PublicIndex >= 0 {
			addrs[ipv4PublicIndex].NodePort = dev.Selected
		}

		if ipv6PrivateIndex >= 0 {
			addrs[ipv6PrivateIndex].NodePort = dev.Selected
		} else if ipv6PublicIndex >= 0 {
			addrs[ipv6PublicIndex].NodePort = dev.Selected
		}
	}

	return sets.New(addrs...)
}

// showAddresses formats a Set[NodeAddress] as "1.2.3.4 (eth0), fe80::1 (eth1)"
func showAddresses(addrs sets.Set[NodeAddress]) string {
	ss := make([]string, 0, len(addrs))
	for addr := range addrs {
		ss = append(ss, addr.String())
	}
	sort.Strings(ss)
	return strings.Join(ss, ", ")
}

// sortedAddresses returns a copy of the addresses sorted by following predicates
// (first predicate matching in this order wins):
// - Primary (e.g. !IFA_F_SECONDARY)
// - Scope, with lower scope going first (e.g. UNIVERSE before LINK)
// - Public addresses before private (e.g. 1.2.3.4 before 192.168.1.1)
// - By address itself (192.168.1.1 before 192.168.1.2)
//
// The sorting order affects which address is marked 'Primary' and which is picked as
// the 'NodePort' address (when --nodeport-addresses is not specified).
func SortedAddresses(addrs []DeviceAddress) []DeviceAddress {
	addrs = slices.Clone(addrs)

	sort.SliceStable(addrs, func(i, j int) bool {
		switch {
		case !addrs[i].Secondary && addrs[j].Secondary:
			return true
		case addrs[i].Secondary && !addrs[j].Secondary:
			return false
		case addrs[i].Scope < addrs[j].Scope:
			return true
		case addrs[i].Scope > addrs[j].Scope:
			return false
		case ip.IsPublicAddr(addrs[i].Addr.AsSlice()) && !ip.IsPublicAddr(addrs[j].Addr.AsSlice()):
			return true
		case !ip.IsPublicAddr(addrs[i].Addr.AsSlice()) && ip.IsPublicAddr(addrs[j].Addr.AsSlice()):
			return false
		default:
			return addrs[i].Addr.Less(addrs[j].Addr)
		}
	})
	return addrs
}