// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mock

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"golang.org/x/time/rate"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/api/helpers"
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
	AssignPrivateIpAddressesVM
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
	mutex             lock.RWMutex
	subnets           map[string]*subnet
	instances         *ipamTypes.InstanceMap
	errors            map[Operation]error
	prefixError       error
	prefixRequests    int
	reportedAvailable map[string]int
	delaySim          *helpers.DelaySimulator
	limiter           *rate.Limiter
}

func NewAPI(subnets []*ipamTypes.Subnet) *API {
	api := &API{
		instances:         ipamTypes.NewInstanceMap(),
		subnets:           map[string]*subnet{},
		errors:            map[Operation]error{},
		reportedAvailable: map[string]int{},
		delaySim:          helpers.NewDelaySimulator(),
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

// ReserveInstanceAddresses reserves the addresses and prefixes of the mock's
// instances in their subnets, so they are not allocated again.
func (a *API) ReserveInstanceAddresses() {
	a.mutex.Lock()
	a.instances.ForeachInterface("", func(_, _ string, iface ipamTypes.Interface) error {
		intf, ok := iface.(*types.AzureInterface)
		if !ok {
			return nil
		}
		s, ok := a.subnets[intf.Subnet.ID]
		if !ok {
			return nil
		}
		s.allocator.Allocate(intf.IP.Addr)
		for _, address := range intf.Addresses {
			s.allocator.Allocate(address.IP.Addr)
		}
		for _, prefix := range intf.Prefixes {
			for addr := prefix.CIDR.Addr(); prefix.CIDR.Contains(addr); addr = addr.Next() {
				s.allocator.Allocate(addr)
			}
		}
		return nil
	})
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
			if available, ok := a.reportedAvailable[sd.ID]; ok {
				sd.AvailableAddresses = available
			}
			subnets[sd.ID] = sd
		}
	}

	return subnets, nil
}

func (a *API) AssignPrivateIpAddressesVM(ctx context.Context, subnetID, interfaceName string, count int, prefixLength int32) error {
	a.rateLimit()
	a.delaySim.Delay(AssignPrivateIpAddressesVM)

	a.mutex.Lock()
	defer a.mutex.Unlock()

	if err, ok := a.errors[AssignPrivateIpAddressesVM]; ok {
		return err
	}

	return a.assignPrivateIpAddressesLocked(subnetID, interfaceName, count, prefixLength, func(intf *types.AzureInterface) bool {
		return intf.Name == interfaceName && intf.GetVMScaleSetName() == ""
	})
}

func (a *API) AssignPrivateIpAddressesVMSS(ctx context.Context, vmName, vmssName, subnetID, interfaceName string, count int, prefixLength int32) error {
	a.rateLimit()
	a.delaySim.Delay(AssignPrivateIpAddressesVMSS)

	a.mutex.Lock()
	defer a.mutex.Unlock()

	if err, ok := a.errors[AssignPrivateIpAddressesVMSS]; ok {
		return err
	}

	return a.assignPrivateIpAddressesLocked(subnetID, interfaceName, count, prefixLength, func(intf *types.AzureInterface) bool {
		return intf.Name == interfaceName && intf.GetVMID() == vmName
	})
}

// SetPrefixError makes prefix requests fail with err, or succeed again if err
// is nil.
func (a *API) SetPrefixError(err error) {
	a.mutex.Lock()
	a.prefixError = err
	a.mutex.Unlock()
}

// PrefixRequests returns how many prefix requests reached an interface.
func (a *API) PrefixRequests() int {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	return a.prefixRequests
}

// SetReportedAvailableAddresses makes GetSubnetsByIDs report available
// addresses for the subnet regardless of how many are actually free.
func (a *API) SetReportedAvailableAddresses(subnetID string, available int) {
	a.mutex.Lock()
	a.reportedAvailable[subnetID] = available
	a.mutex.Unlock()
}

// SubnetIsFullError returns the error Azure returns when a subnet can't
// satisfy a request.
func SubnetIsFullError() error {
	return &azcore.ResponseError{ErrorCode: "SubnetIsFull", StatusCode: http.StatusBadRequest}
}

func (a *API) assignPrivateIpAddressesLocked(subnetID, interfaceName string, count int, prefixLength int32, match func(intf *types.AzureInterface) bool) error {
	if prefixLength > 0 && prefixLength != types.PrefixLengthIPv4 {
		return fmt.Errorf("unsupported prefix length %d", prefixLength)
	}

	foundInterface := false
	instances := a.instances.DeepCopy()
	err := instances.ForeachInterface("", func(id, _ string, iface ipamTypes.Interface) error {
		intf, ok := iface.(*types.AzureInterface)
		if !ok {
			return fmt.Errorf("invalid interface object")
		}

		if !match(intf) {
			return nil
		}

		if len(intf.Addresses)+len(intf.Prefixes)+count > types.InterfaceAddressLimit {
			return fmt.Errorf("exceeded interface limit")
		}

		s, ok := a.subnets[subnetID]
		if !ok {
			return fmt.Errorf("subnet %s does not exist", subnetID)
		}

		if prefixLength > 0 {
			a.prefixRequests++
			if a.prefixError != nil {
				return a.prefixError
			}
			prefixes, err := allocatePrefixes(s, count)
			if err != nil {
				return err
			}
			for _, prefix := range prefixes {
				intf.Prefixes = append(intf.Prefixes, types.AzurePrefix{
					CIDR:  iputil.PrefixFrom(prefix),
					State: types.StateSucceeded,
				})
			}
		} else {
			if s.allocator.Free() < count {
				return SubnetIsFullError()
			}
			for range count {
				ip, err := s.allocator.AllocateNext()
				if err != nil {
					return err
				}
				intf.Addresses = append(intf.Addresses, types.AzureAddress{
					IP:    iputil.AddrFrom(ip),
					State: types.StateSucceeded,
				})
			}
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

// allocatePrefixes takes count aligned /28s from the subnet, never its first
// or last /28, or none if not enough are free.
func allocatePrefixes(s *subnet, count int) ([]netip.Prefix, error) {
	cidr := s.allocator.CIDR()
	if cidr.Bits() > types.PrefixLengthIPv4 {
		return nil, SubnetIsFullError()
	}
	blocks := 1 << (types.PrefixLengthIPv4 - cidr.Bits())

	var prefixes []netip.Prefix
	for block := 1; block < blocks-1 && len(prefixes) < count; block++ {
		prefix := netip.PrefixFrom(nthAddr(cidr.Addr(), block*types.PrefixSizeIPv4), types.PrefixLengthIPv4)
		free := true
		for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
			if s.allocator.Has(addr) {
				free = false
				break
			}
		}
		if free {
			prefixes = append(prefixes, prefix)
		}
	}
	if len(prefixes) < count {
		return nil, SubnetIsFullError()
	}

	for _, prefix := range prefixes {
		for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
			if err := s.allocator.Allocate(addr); err != nil {
				return nil, err
			}
		}
	}
	return prefixes, nil
}

func nthAddr(addr netip.Addr, n int) netip.Addr {
	for range n {
		addr = addr.Next()
	}
	return addr
}

func (a *API) UnassignPrivateIpAddressesVM(ctx context.Context, interfaceName string, addresses []netip.Addr) error {
	a.rateLimit()
	a.delaySim.Delay(UnassignPrivateIpAddressesVM)

	a.mutex.Lock()
	defer a.mutex.Unlock()

	if err, ok := a.errors[UnassignPrivateIpAddressesVM]; ok {
		return err
	}

	return a.unassignPrivateIpAddressesLocked(interfaceName, addresses, func(intf *types.AzureInterface) bool {
		return intf.Name == interfaceName && intf.GetVMScaleSetName() == ""
	})
}

func (a *API) UnassignPrivateIpAddressesVMSS(ctx context.Context, instanceID, vmssName, interfaceName string, addresses []netip.Addr) error {
	a.rateLimit()
	a.delaySim.Delay(UnassignPrivateIpAddressesVMSS)

	a.mutex.Lock()
	defer a.mutex.Unlock()

	if err, ok := a.errors[UnassignPrivateIpAddressesVMSS]; ok {
		return err
	}

	return a.unassignPrivateIpAddressesLocked(interfaceName, addresses, func(intf *types.AzureInterface) bool {
		return intf.Name == interfaceName && intf.GetVMID() == instanceID && intf.GetVMScaleSetName() == vmssName
	})
}

func (a *API) unassignPrivateIpAddressesLocked(interfaceName string, addresses []netip.Addr, match func(intf *types.AzureInterface) bool) error {
	foundInterface := false
	instances := a.instances.DeepCopy()
	err := instances.ForeachInterface("", func(id, _ string, iface ipamTypes.Interface) error {
		intf, ok := iface.(*types.AzureInterface)
		if !ok {
			return fmt.Errorf("invalid interface object")
		}

		if !match(intf) {
			return nil
		}

		intf.Addresses = slices.DeleteFunc(intf.Addresses, func(addr types.AzureAddress) bool {
			if !slices.Contains(addresses, addr.IP.Addr) {
				return false
			}
			if s, ok := a.subnets[intf.Subnet.ID]; ok {
				s.allocator.Release(addr.IP.Addr)
			}
			return true
		})

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
