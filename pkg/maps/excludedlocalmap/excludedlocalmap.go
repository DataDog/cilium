// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package excludedlocalmap

import (
	"fmt"
	"net"
	"sync"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/option"
)

const (
	MapName = "cilium_excluded_local_addrs"

	// MaxEntries represents the maximum number of excluded local addresses
	MaxEntries = 64
)

var (
	// excludedLocalMap represents the BPF map for excluded local addresses
	excludedLocalMap     *bpf.Map
	excludedLocalMapOnce sync.Once
)

// ExcludedLocalMap returns the excluded local addresses BPF map
func ExcludedLocalMap() *bpf.Map {
	excludedLocalMapOnce.Do(func() {
		excludedLocalMap = bpf.NewMap(MapName,
			ebpf.Hash,
			&ExcludedLocalKey{},
			&ExcludedLocalValue{},
			MaxEntries,
			0,
		).WithCache().WithPressureMetric().
			WithEvents(option.Config.GetEventBufferConfig(MapName))
	})
	return excludedLocalMap
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

func (k *ExcludedLocalKey) New() bpf.MapKey { return &ExcludedLocalKey{} }

// ExcludedLocalValue represents the value for the excluded local addresses map
// Just a simple flag to indicate presence
type ExcludedLocalValue struct {
	Flag uint8 `align:"flag"`
}

func (v *ExcludedLocalValue) New() bpf.MapValue { return &ExcludedLocalValue{} }

// String returns the human readable representation of an ExcludedLocalValue
func (v *ExcludedLocalValue) String() string {
	return fmt.Sprintf("flag=%d", v.Flag)
}

// AddEntry adds an excluded local address to the map
func AddEntry(ip net.IP) error {
	key := NewExcludedLocalKey(ip)
	value := &ExcludedLocalValue{Flag: 1}
	return ExcludedLocalMap().Update(key, value)
}

// SyncEntry checks if an excluded local address exists in the map and adds one if needed.
// Returns boolean indicating if a new entry was added and an error.
func SyncEntry(ip net.IP) (bool, error) {
	key := NewExcludedLocalKey(ip)
	_, err := ExcludedLocalMap().Lookup(key)
	if err != nil {
		// Entry doesn't exist, add it
		err = AddEntry(ip)
		if err == nil {
			return true, nil
		}
	}
	return false, err
}

// DeleteEntry deletes a single map entry
func DeleteEntry(ip net.IP) error {
	key := NewExcludedLocalKey(ip)
	return ExcludedLocalMap().Delete(key)
}

// DumpToMap dumps the contents of the excluded local addresses map into a map and returns it
func DumpToMap() (map[string]ExcludedLocalValue, error) {
	m := map[string]ExcludedLocalValue{}
	callback := func(key bpf.MapKey, value bpf.MapValue) {
		if info, ok := value.(*ExcludedLocalValue); ok {
			if excludedKey, ok := key.(*ExcludedLocalKey); ok {
				m[excludedKey.ToIP().String()] = *info
			}
		}
	}

	if err := ExcludedLocalMap().DumpWithCallback(callback); err != nil {
		return nil, fmt.Errorf("unable to read BPF excluded local addresses list: %w", err)
	}

	return m, nil
}

// Exists checks if an IP address exists in the excluded local addresses map
func Exists(ip net.IP) bool {
	key := NewExcludedLocalKey(ip)
	_, err := ExcludedLocalMap().Lookup(key)
	return err == nil
}
