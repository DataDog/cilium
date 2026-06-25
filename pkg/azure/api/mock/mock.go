// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mock

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v9"
	"golang.org/x/time/rate"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/api/helpers"
	azureAPI "github.com/cilium/cilium/pkg/azure/api"
	"github.com/cilium/cilium/pkg/azure/types"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam/service/ipallocator"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/lock"
)

// Operation is an Azure API operation that this mock API supports
type Operation int

const (
	AllOperations Operation = iota
	ListVMNetworkInterfaces
	ListAllNetworkInterfaces
	GetSubnetsByIDs
	AssignPrivateIpAddressesVMSS
	UnassignPrivateIpAddressesVM
	UnassignPrivateIpAddressesVMSS
	MaxOperation
)

type subnet struct {
	subnet    *ipamTypes.Subnet
	allocator *ipallocator.Range
}

type API struct {
	mutex     lock.RWMutex
	subnets   map[string]*subnet
	instances *ipamTypes.InstanceMap
	errors    map[Operation]error
	delaySim  *helpers.DelaySimulator
	limiter   *rate.Limiter
	// primaryIPs records the identifiers treated as primary, keyed by interface ID.
	primaryIPs map[string]map[string]struct{}
}

func NewAPI(subnets []*ipamTypes.Subnet) *API {
	api := &API{
		instances:  ipamTypes.NewInstanceMap(),
		subnets:    map[string]*subnet{},
		errors:     map[Operation]error{},
		delaySim:   helpers.NewDelaySimulator(),
		primaryIPs: map[string]map[string]struct{}{},
	}

	api.UpdateSubnets(subnets)

	return api
}

func (a *API) UpdateSubnets(subnets []*ipamTypes.Subnet) {
	a.mutex.Lock()
	a.subnets = map[string]*subnet{}
	for _, s := range subnets {
		prefix, _ := netip.ParsePrefix(s.CIDR.String())

		a.subnets[s.ID] = &subnet{
			subnet:    s.DeepCopy(),
			allocator: ipallocator.NewCIDRRange(prefix),
		}
	}
	a.mutex.Unlock()
}

func (a *API) UpdateInstances(instances *ipamTypes.InstanceMap) {
	a.mutex.Lock()
	a.updateInstancesLocked(instances)
	a.mutex.Unlock()
}

func (a *API) updateInstancesLocked(instances *ipamTypes.InstanceMap) {
	a.instances = instances.DeepCopy()
}

// SetMockError modifies the mock API to return an error for a particular
// operation
func (a *API) SetMockError(op Operation, err error) {
	a.mutex.Lock()
	a.errors[op] = err
	a.mutex.Unlock()
}

// SetDelay specifies the delay which should be simulated for an individual
// Azure API operation
func (a *API) SetDelay(op Operation, delay time.Duration) {
	if op == AllOperations {
		for op := AllOperations + 1; op < MaxOperation; op++ {
			a.delaySim.SetDelay(op, delay)
		}
	} else {
		a.delaySim.SetDelay(op, delay)
	}
}

// SetLimiter adds a rate limiter to all simulated API calls
func (a *API) SetLimiter(limit float64, burst int) {
	a.limiter = rate.NewLimiter(rate.Limit(limit), burst)
}

func (a *API) rateLimit() {
	a.mutex.RLock()
	if a.limiter == nil {
		a.mutex.RUnlock()
		return
	}

	r := a.limiter.Reserve()
	a.mutex.RUnlock()
	if delay := r.Delay(); delay != time.Duration(0) && delay != rate.InfDuration {
		time.Sleep(delay)
	}
}

func (a *API) GetSubnetsByIDs(ctx context.Context, nodeSubnetIDs []string) (ipamTypes.SubnetMap, error) {
	a.rateLimit()
	a.delaySim.Delay(GetSubnetsByIDs)

	a.mutex.RLock()
	defer a.mutex.RUnlock()

	if err, ok := a.errors[GetSubnetsByIDs]; ok {
		return nil, err
	}

	subnets := ipamTypes.SubnetMap{}

	// Only return subnets that match the requested subnet IDs
	subnetIDSet := sets.New[string](nodeSubnetIDs...)

	for _, s := range a.subnets {
		if subnetIDSet.Has(s.subnet.ID) {
			sd := s.subnet.DeepCopy()
			sd.AvailableAddresses = s.allocator.Free()
			subnets[sd.ID] = sd
		}
	}

	return subnets, nil
}

func (a *API) AssignPrivateIpAddressesVM(ctx context.Context, subnetID, interfaceName string, addresses int) error {
	a.rateLimit()

	a.mutex.Lock()
	defer a.mutex.Unlock()

	foundInterface := false
	instances := a.instances.DeepCopy()
	err := instances.ForeachInterface("", func(id, _ string, iface ipamTypes.Interface) error {
		intf, ok := iface.(*types.AzureInterface)
		if !ok {
			return fmt.Errorf("invalid interface object")
		}

		// Standalone-VM interfaces are not part of a scale set.
		if intf.Name != interfaceName || intf.GetVMScaleSetName() != "" {
			return nil
		}

		if len(intf.Addresses)+addresses > types.InterfaceAddressLimit {
			return fmt.Errorf("exceeded interface limit")
		}

		s, ok := a.subnets[subnetID]
		if !ok {
			return fmt.Errorf("subnet %s does not exist", subnetID)
		}

		for range addresses {
			ip, err := s.allocator.AllocateNext()
			if err != nil {
				panic("Unable to allocate IP from allocator")
			}
			intf.Addresses = append(intf.Addresses, types.AzureAddress{
				IP:     iputil.AddrFrom(ip),
				Subnet: subnetID, //nolint:staticcheck // deprecated mirror; matches parseInterface, see https://github.com/cilium/cilium/issues/46074
				State:  types.StateSucceeded,
			})
		}

		foundInterface = true
		return nil
	})
	if err != nil {
		return err
	}

	a.updateInstancesLocked(instances)

	if !foundInterface {
		return fmt.Errorf("interface %s not found", interfaceName)
	}

	return nil
}

func (a *API) AssignPrivateIpAddressesVMSS(ctx context.Context, vmName, vmssName, subnetID, interfaceName string, addresses int) error {
	a.rateLimit()
	a.delaySim.Delay(AssignPrivateIpAddressesVMSS)

	a.mutex.Lock()
	defer a.mutex.Unlock()

	if err, ok := a.errors[AssignPrivateIpAddressesVMSS]; ok {
		return err
	}

	foundInterface := false
	instances := a.instances.DeepCopy()
	err := instances.ForeachInterface("", func(id, _ string, iface ipamTypes.Interface) error {
		intf, ok := iface.(*types.AzureInterface)
		if !ok {
			return fmt.Errorf("invalid interface object")
		}

		if intf.Name != interfaceName || intf.GetVMID() != vmName {
			return nil
		}

		if len(intf.Addresses)+addresses > types.InterfaceAddressLimit {
			return fmt.Errorf("exceeded interface limit")
		}

		s, ok := a.subnets[subnetID]
		if !ok {
			return fmt.Errorf("subnet %s does not exist", subnetID)
		}

		for range addresses {
			ip, err := s.allocator.AllocateNext()
			if err != nil {
				panic("Unable to allocate IP from allocator")
			}
			intf.Addresses = append(intf.Addresses, types.AzureAddress{
				IP:     iputil.AddrFrom(ip),
				Subnet: subnetID, //nolint:staticcheck // deprecated mirror; matches parseInterface, see https://github.com/cilium/cilium/issues/46074
				State:  types.StateSucceeded,
			})
		}

		foundInterface = true
		return nil
	})
	if err != nil {
		return err
	}

	a.updateInstancesLocked(instances)

	if !foundInterface {
		return fmt.Errorf("interface %s not found", interfaceName)
	}

	return nil
}

// SetPrimaryIPs marks the given identifiers as primary on the named interface,
// so Unassign* returns *api.PrimaryReleaseError when asked to release them.
func (a *API) SetPrimaryIPs(interfaceID string, items ...string) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if a.primaryIPs == nil {
		a.primaryIPs = map[string]map[string]struct{}{}
	}
	set, ok := a.primaryIPs[interfaceID]
	if !ok {
		set = map[string]struct{}{}
		a.primaryIPs[interfaceID] = set
	}
	for _, item := range items {
		set[item] = struct{}{}
	}
}

// findPrimaryBlocked returns the subset of items recorded as primary on
// interfaceID via SetPrimaryIPs. Caller must hold a.mutex.
func (a *API) findPrimaryBlocked(interfaceID string, items []string) []string {
	set, ok := a.primaryIPs[interfaceID]
	if !ok {
		return nil
	}
	var blocked []string
	for _, item := range items {
		if _, isPrimary := set[item]; isPrimary {
			blocked = append(blocked, item)
		}
	}
	return blocked
}

func (a *API) UnassignPrivateIpAddressesVM(ctx context.Context, interfaceName string, addresses []string) error {
	a.rateLimit()
	a.delaySim.Delay(UnassignPrivateIpAddressesVM)

	a.mutex.Lock()
	defer a.mutex.Unlock()

	if err, ok := a.errors[UnassignPrivateIpAddressesVM]; ok {
		return err
	}
	if len(addresses) == 0 {
		return nil
	}

	if blocked := a.findPrimaryBlocked(interfaceName, addresses); len(blocked) > 0 {
		return &azureAPI.PrimaryReleaseError{InterfaceName: interfaceName, Items: blocked}
	}

	releaseSet := make(map[string]struct{}, len(addresses))
	for _, ip := range addresses {
		releaseSet[ip] = struct{}{}
	}

	instances := a.instances.DeepCopy()
	foundInterface := false
	err := instances.ForeachInterface("", func(_, _ string, iface ipamTypes.Interface) error {
		intf, ok := iface.(*types.AzureInterface)
		if !ok {
			return fmt.Errorf("invalid interface object")
		}
		if intf.Name != interfaceName || intf.GetVMScaleSetName() != "" {
			return nil
		}
		foundInterface = true
		intf.Addresses = a.dropAddressesByIP(intf, releaseSet)
		return nil
	})
	if err != nil {
		return err
	}
	if !foundInterface {
		return fmt.Errorf("interface %s not found", interfaceName)
	}

	a.updateInstancesLocked(instances)
	return nil
}

func (a *API) UnassignPrivateIpAddressesVMSS(ctx context.Context, instanceID, vmssName, interfaceName string, ipConfigNames []string) error {
	a.rateLimit()
	a.delaySim.Delay(UnassignPrivateIpAddressesVMSS)

	a.mutex.Lock()
	defer a.mutex.Unlock()

	if err, ok := a.errors[UnassignPrivateIpAddressesVMSS]; ok {
		return err
	}
	if len(ipConfigNames) == 0 {
		return nil
	}

	releaseNames := make(map[string]struct{}, len(ipConfigNames))
	for _, name := range ipConfigNames {
		releaseNames[name] = struct{}{}
	}

	// Run the primary guard before mutating: dropAddressesByIPConfigName frees
	// IPs to the shared allocator, which a fail-closed return would not undo.
	var ifaceID string
	foundInterface := false
	a.instances.ForeachInterface("", func(_, _ string, iface ipamTypes.Interface) error {
		intf, ok := iface.(*types.AzureInterface)
		if !ok {
			return nil
		}
		if intf.Name != interfaceName || intf.GetVMID() != instanceID || intf.GetVMScaleSetName() != vmssName {
			return nil
		}
		foundInterface = true
		ifaceID = intf.ID
		return nil
	})
	if !foundInterface {
		return fmt.Errorf("interface %s not found on VM %s in VMSS %s", interfaceName, instanceID, vmssName)
	}

	if blocked := a.findPrimaryBlocked(ifaceID, ipConfigNames); len(blocked) > 0 {
		return &azureAPI.PrimaryReleaseError{InterfaceName: interfaceName, Items: blocked}
	}

	instances := a.instances.DeepCopy()
	err := instances.ForeachInterface("", func(_, _ string, iface ipamTypes.Interface) error {
		intf, ok := iface.(*types.AzureInterface)
		if !ok {
			return fmt.Errorf("invalid interface object")
		}
		if intf.Name != interfaceName || intf.GetVMID() != instanceID || intf.GetVMScaleSetName() != vmssName {
			return nil
		}
		intf.Addresses = a.dropAddressesByIPConfigName(intf, releaseNames)
		return nil
	})
	if err != nil {
		return err
	}

	a.updateInstancesLocked(instances)
	return nil
}

// dropAddressesByIP removes addresses in releaseSet, freeing their IPs.
// Caller must hold a.mutex.
func (a *API) dropAddressesByIP(intf *types.AzureInterface, releaseSet map[string]struct{}) []types.AzureAddress {
	kept := make([]types.AzureAddress, 0, len(intf.Addresses))
	for _, addr := range intf.Addresses {
		if _, drop := releaseSet[addr.IP.String()]; drop {
			a.releaseToSubnetAllocator(addr)
			continue
		}
		kept = append(kept, addr)
	}
	return kept
}

// dropAddressesByIPConfigName removes addresses whose IPConfigName is in
// releaseNames, freeing their IPs. Caller must hold a.mutex.
func (a *API) dropAddressesByIPConfigName(intf *types.AzureInterface, releaseNames map[string]struct{}) []types.AzureAddress {
	kept := make([]types.AzureAddress, 0, len(intf.Addresses))
	for _, addr := range intf.Addresses {
		if _, drop := releaseNames[addr.IPConfigName()]; drop {
			a.releaseToSubnetAllocator(addr)
			continue
		}
		kept = append(kept, addr)
	}
	return kept
}

// releaseToSubnetAllocator returns addr.IP to the subnet allocator if known.
// Caller must hold a.mutex.
func (a *API) releaseToSubnetAllocator(addr types.AzureAddress) {
	s, ok := a.subnets[addr.Subnet]
	if !ok {
		return
	}
	if !addr.IP.Addr.IsValid() {
		return
	}
	s.allocator.Release(addr.IP.Addr)
}

func (a *API) AssignPublicIPAddressesVMSS(ctx context.Context, instanceID, vmssName string, publicIpTags ipamTypes.Tags) (netip.Addr, error) {
	a.rateLimit()
	return netip.MustParseAddr("192.0.2.1"), nil
}

func (a *API) AssignPublicIPAddressesVM(ctx context.Context, instanceID string, publicIpTags ipamTypes.Tags) (netip.Addr, error) {
	a.rateLimit()
	return netip.MustParseAddr("192.0.2.1"), nil
}

// ListAllNetworkInterfaces returns a dummy slice since mock doesn't use real network interfaces
// The mock API uses instances directly rather than armnetwork.Interface objects
func (a *API) ListAllNetworkInterfaces(ctx context.Context) ([]*armnetwork.Interface, error) {
	a.rateLimit()
	a.delaySim.Delay(ListAllNetworkInterfaces)

	a.mutex.RLock()
	defer a.mutex.RUnlock()

	if err, ok := a.errors[ListAllNetworkInterfaces]; ok {
		return nil, err
	}

	// Return an empty slice - the mock doesn't use actual armnetwork.Interface objects
	// ParseInterfacesIntoInstanceMap will handle returning the mock instances
	return []*armnetwork.Interface{}, nil
}

// ParseInterfacesIntoInstanceMap ignores the input and returns the mock's instances
// The mock API doesn't use real armnetwork.Interface objects
func (a *API) ParseInterfacesIntoInstanceMap(networkInterfaces []*armnetwork.Interface, subnets ipamTypes.SubnetMap) *ipamTypes.InstanceMap {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	// Return the mock's instances regardless of input
	return a.instances.DeepCopy()
}

// ListVMNetworkInterfaces returns a single sentinel armnetwork.Interface whose
// ID carries the requested instanceID, so ParseInterfacesIntoInstance can
// recover which instance to return without making another API call.
func (a *API) ListVMNetworkInterfaces(ctx context.Context, instanceID string) ([]*armnetwork.Interface, error) {
	a.rateLimit()
	a.delaySim.Delay(ListVMNetworkInterfaces)

	a.mutex.RLock()
	defer a.mutex.RUnlock()

	if err, ok := a.errors[ListVMNetworkInterfaces]; ok {
		return nil, err
	}

	if !a.instances.Exists(instanceID) {
		return nil, fmt.Errorf("instance %s not found", instanceID)
	}

	id := instanceID
	return []*armnetwork.Interface{{ID: &id}}, nil
}

// ParseInterfacesIntoInstance recovers the instanceID from the sentinel
// produced by ListVMNetworkInterfaces and returns the mock's instance.
func (a *API) ParseInterfacesIntoInstance(networkInterfaces []*armnetwork.Interface, subnets ipamTypes.SubnetMap) *ipamTypes.Instance {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	instance := ipamTypes.Instance{Interfaces: map[string]ipamTypes.Interface{}}
	if len(networkInterfaces) == 0 || networkInterfaces[0].ID == nil {
		return &instance
	}
	instanceID := *networkInterfaces[0].ID

	_ = a.instances.ForeachInterface(instanceID, func(_, interfaceID string, iface ipamTypes.Interface) error {
		instance.Interfaces[interfaceID] = iface
		return nil
	})
	return instance.DeepCopy()
}
