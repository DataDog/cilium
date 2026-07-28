// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/ipam/types"
)

func TestForeachAddresses(t *testing.T) {
	m := types.NewInstanceMap()
	m.Update("i-1", types.InterfaceRevision{
		Resource: &AzureInterface{ID: "1", Addresses: []AzureAddress{
			{IP: "1.1.1.1"},
			{IP: "2.2.2.2"},
		},
		}})
	m.Update("i-2", types.InterfaceRevision{
		Resource: &AzureInterface{ID: "1", Addresses: []AzureAddress{
			{IP: "3.3.3.3"},
			{IP: "4.4.4.4"},
		},
		}})

	// Iterate over all instances
	addresses := 0
	m.ForeachAddress("", func(instanceID, interfaceID, ip, poolID string, address types.Address) error {
		addresses++
		return nil
	})
	require.Equal(t, 4, addresses)

	// Iterate over "i-1"
	addresses = 0
	m.ForeachAddress("i-1", func(instanceID, interfaceID, ip, poolID string, address types.Address) error {
		addresses++
		return nil
	})
	require.Equal(t, 2, addresses)

	// Iterate over all interfaces
	interfaces := 0
	m.ForeachInterface("", func(instanceID, interfaceID string, interfaceObj types.InterfaceRevision) error {
		interfaces++
		return nil
	})
	require.Equal(t, 2, interfaces)
}

func TestExtractIDs(t *testing.T) {
	tests := []struct {
		name             string
		resourceID       string
		expectedRG       string
		expectedVMID     string
		expectedVMSSName string
	}{
		{
			name:             "VMSS network interface",
			resourceID:       "/subscriptions/xxx/resourceGroups/MC_aks-test_aks-test_westeurope/providers/Microsoft.Compute/virtualMachineScaleSets/aks-nodepool1-10706209-vmss/virtualMachines/3/networkInterfaces/aks-nodepool1-10706209-vmss",
			expectedRG:       "MC_aks-test_aks-test_westeurope",
			expectedVMID:     "3",
			expectedVMSSName: "aks-nodepool1-10706209-vmss",
		},
		{
			name:             "Standalone VM network interface",
			resourceID:       "/subscriptions/xxx/resourceGroups/az-test-rg/providers/Microsoft.Network/networkInterfaces/pods-interface",
			expectedRG:       "az-test-rg",
			expectedVMID:     "",
			expectedVMSSName: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			intf := AzureInterface{}
			intf.ID = tt.resourceID

			require.Equal(t, tt.expectedRG, intf.GetResourceGroup())
			require.Equal(t, tt.expectedVMID, intf.GetVMID())
			require.Equal(t, tt.expectedVMSSName, intf.GetVMScaleSetName())
		})
	}
}

// State the status carries but does not serialize cannot survive the apiserver,
// so the operator's freshly built status would never compare equal to the copy
// it reads back and every IPAM sync would write /status.
func TestAzureStatusHasNoUnserializedState(t *testing.T) {
	status := reflect.TypeFor[AzureStatus]()

	var check func(ty reflect.Type)
	check = func(ty reflect.Type) {
		// Only the types declared here are walked.
		for ty.Kind() == reflect.Pointer || ty.Kind() == reflect.Slice || ty.Kind() == reflect.Array || ty.Kind() == reflect.Map {
			ty = ty.Elem()
		}
		if ty.Kind() != reflect.Struct || ty.PkgPath() != status.PkgPath() {
			return
		}
		for i := range ty.NumField() {
			field := ty.Field(i)
			require.True(t, field.IsExported(), "%s.%s is unexported", ty.Name(), field.Name)
			require.NotEqual(t, "-", field.Tag.Get("json"), "%s.%s is excluded from JSON", ty.Name(), field.Name)
			check(field.Type)
		}
	}
	check(status)
}

// A round trip must not perturb the interface, or the operator's DeepEqual
// write-skip gate breaks.
func TestAzureInterfaceJSONRoundTrip(t *testing.T) {
	base := &AzureInterface{
		ID:            "/subscriptions/xxx/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss1/virtualMachines/0/networkInterfaces/vmss1",
		Name:          "eth0",
		MAC:           "aa:bb:cc:dd:ee:ff",
		State:         StateSucceeded,
		SecurityGroup: "sg1",
		Addresses: []AzureAddress{
			{IP: "10.0.0.2", Subnet: "s-1", State: StateSucceeded},
			{IP: "10.0.0.3", Subnet: "s-1", State: StateSucceeded},
		},
		GatewayIP: "10.0.0.1",
		Gateway:   "10.0.0.1",
		CIDR:      "10.0.0.0/24",
	}

	marshalled, err := json.Marshal(base)
	require.NoError(t, err)
	var roundTripped AzureInterface
	require.NoError(t, json.Unmarshal(marshalled, &roundTripped))

	require.Equal(t, *base, roundTripped)
	require.True(t, base.DeepEqual(&roundTripped))

	// A difference in any field, including the nested types, must be visible to
	// DeepEqual or the operator skips a /status write it owes.
	mutations := map[string]func(*AzureInterface){
		"ID":                 func(a *AzureInterface) { a.ID = "intf-2" },
		"Name":               func(a *AzureInterface) { a.Name = "eth1" },
		"MAC":                func(a *AzureInterface) { a.MAC = "ff:ee:dd:cc:bb:aa" },
		"State":              func(a *AzureInterface) { a.State = "failed" },
		"SecurityGroup":      func(a *AzureInterface) { a.SecurityGroup = "sg2" },
		"Addresses[].IP":     func(a *AzureInterface) { a.Addresses[0].IP = "10.0.0.9" },
		"Addresses[].Subnet": func(a *AzureInterface) { a.Addresses[0].Subnet = "s-9" },
		"Addresses[].State":  func(a *AzureInterface) { a.Addresses[0].State = "failed" },
		"GatewayIP":          func(a *AzureInterface) { a.GatewayIP = "10.0.1.1" },
		"Gateway":            func(a *AzureInterface) { a.Gateway = "10.0.1.1" },
		"CIDR":               func(a *AzureInterface) { a.CIDR = "10.0.1.0/24" },

		"Addresses removed":   func(a *AzureInterface) { a.Addresses = nil },
		"Addresses reordered": func(a *AzureInterface) { a.Addresses[0], a.Addresses[1] = a.Addresses[1], a.Addresses[0] },
	}

	for _, path := range slices.Sorted(maps.Keys(mutations)) {
		t.Run(path, func(t *testing.T) {
			other := roundTripped.DeepCopy()
			mutations[path](other)
			require.False(t, base.DeepEqual(other))
		})
	}
}
