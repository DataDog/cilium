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

	MaxEntries = 64
)

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

type ExcludedLocalKey struct {
	bpf.EndpointKey
}

func NewExcludedLocalKey(ip net.IP) *ExcludedLocalKey {
	return &ExcludedLocalKey{
		EndpointKey: bpf.NewEndpointKey(ip, 0),
	}
}

// ExcludedLocalValue is a simple flag to indicate presence
type ExcludedLocalValue struct {
	Flag uint8 `align:"flag"`
}

func (v *ExcludedLocalValue) String() string {
	return fmt.Sprintf("flag=%d", v.Flag)
}

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

func (m *ExcludedLocalMap) DeleteEntry(ip net.IP) error {
	key := NewExcludedLocalKey(ip)
	return m.bpfMap.Delete(key)
}

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
