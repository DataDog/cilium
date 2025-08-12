// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package excludedlocalmap

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
)

const (
	MapName = "cilium_excluded_local_addrs"

	// MaxEntries represents the maximum number of excluded local addresses
	MaxEntries = 64
)

// ExcludedLocalMap manages excluded local addresses
type ExcludedLocalMap struct {
	bpfMap *ebpf.Map
}

func (m *ExcludedLocalMap) init() error {
	m.bpfMap = ebpf.NewMap(&ebpf.MapSpec{
		Name:       MapName,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(ExcludedLocalKey{})),
		ValueSize:  uint32(unsafe.Sizeof(ExcludedLocalValue{})),
		MaxEntries: MaxEntries,
		Flags:      0,
		Pinning:    ebpf.PinByName,
	})

	if err := m.bpfMap.OpenOrCreate(); err != nil {
		return fmt.Errorf("failed to init bpf map: %w", err)
	}

	return nil
}

func (m *ExcludedLocalMap) close() error {
	if m.bpfMap != nil {
		return m.bpfMap.Close()
	}
	return nil
}

// ExcludedLocalKey represents the key for the excluded local addresses map
// Must be in sync with struct endpoint_key in <bpf/lib/common.h>
type ExcludedLocalKey struct {
	bpf.EndpointKey
}

// NewExcludedLocalKey returns an ExcludedLocalKey based on the provided IP address
func NewExcludedLocalKey(ip net.IP) *ExcludedLocalKey {
	return &ExcludedLocalKey{
		EndpointKey: bpf.NewEndpointKey(ip, 0),
	}
}

// ExcludedLocalValue represents the value for the excluded local addresses map
// Just a simple flag to indicate presence
type ExcludedLocalValue struct {
	Flag uint8 `align:"flag"`
}

// String returns the human readable representation of an ExcludedLocalValue
func (v *ExcludedLocalValue) String() string {
	return fmt.Sprintf("flag=%d", v.Flag)
}

// SyncEntry checks if an excluded local address exists in the map and adds one if needed.
// Returns boolean indicating if a new entry was added and an error.
func (m *ExcludedLocalMap) SyncEntry(ip net.IP) (bool, error) {
	key := NewExcludedLocalKey(ip)
	var value ExcludedLocalValue
	err := m.bpfMap.Lookup(key, &value)
	if err != nil {
		// Entry doesn't exist, add it
		newValue := ExcludedLocalValue{Flag: 1}
		err = m.bpfMap.Update(key, newValue, 0)
		if err == nil {
			return true, nil
		}
	}
	return false, err
}

// DeleteEntry deletes a single map entry
func (m *ExcludedLocalMap) DeleteEntry(ip net.IP) error {
	key := NewExcludedLocalKey(ip)
	return m.bpfMap.Delete(key)
}

// DumpToMap dumps the contents of the excluded local addresses map into a map and returns it
func (m *ExcludedLocalMap) DumpToMap() (map[string]ExcludedLocalValue, error) {
	result := map[string]ExcludedLocalValue{}

	iter := m.bpfMap.Iterate()
	var key ExcludedLocalKey
	var value ExcludedLocalValue

	for iter.Next(&key, &value) {
		result[key.ToIP().String()] = value
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("unable to read BPF excluded local addresses list: %w", err)
	}

	return result, nil
}

// Exists checks if an IP address exists in the excluded local addresses map
func (m *ExcludedLocalMap) Exists(ip net.IP) bool {
	key := NewExcludedLocalKey(ip)
	var value ExcludedLocalValue
	err := m.bpfMap.Lookup(key, &value)
	return err == nil
}
