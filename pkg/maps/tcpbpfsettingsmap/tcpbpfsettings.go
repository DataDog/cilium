// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tcpbpf

import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/option"
)

const (
	MapName = "tcp_settings"

	MapSize = lxcmap.MaxEntries
)

type TCPSettingsId struct {
	Id uint64 `align:"id"`
}

func (k *TCPSettingsId) GetKeyPtr() unsafe.Pointer  { return unsafe.Pointer(k) }
func (k *TCPSettingsId) NewValue() bpf.MapValue     { return &TCPSettingsInfo{} }
func (k *TCPSettingsId) String() string             { return fmt.Sprintf("%d", int(k.Id)) }
func (k *TCPSettingsId) DeepCopyMapKey() bpf.MapKey { return &TCPSettingsId{k.Id} }

type TCPSettingsInfo struct {
	InitialTCPRTO uint64 `align:"initial_tcp_rto"`
}

func (v *TCPSettingsInfo) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *TCPSettingsInfo) String() string              { return fmt.Sprintf("%d", int(v.InitialTCPRTO)) }
func (v *TCPSettingsInfo) DeepCopyMapValue() bpf.MapValue {
	return &TCPSettingsInfo{v.InitialTCPRTO}
}

var (
	tcpSettingsMap     *bpf.Map
	tcpSettingsMapInit = &sync.Once{}
)

func TcpSettingsMap() *bpf.Map {
	tcpSettingsMapInit.Do(func() {
		tcpSettingsMap = bpf.NewMap(
			MapName,
			bpf.MapTypeHash,
			&TCPSettingsId{}, int(unsafe.Sizeof(TCPSettingsId{})),
			&TCPSettingsInfo{}, int(unsafe.Sizeof(TCPSettingsInfo{})),
			MapSize,
			bpf.BPF_F_NO_PREALLOC, 0,
			bpf.ConvertKeyValue,
		).WithCache().WithPressureMetric().
			WithEvents(option.Config.GetEventBufferConfig(MapName))
	})

	return tcpSettingsMap
}

func Update(Id uint16, Bps uint64) error {
	return TcpSettingsMap().Update(
		&TCPSettingsId{Id: uint64(Id)},
		&TCPSettingsInfo{InitialTCPRTO: Bps})
}

func Delete(Id uint16) error {
	return TcpSettingsMap().Delete(
		&TCPSettingsId{Id: uint64(Id)})
}

func SilentDelete(Id uint16) error {
	_, err := TcpSettingsMap().SilentDelete(
		&TCPSettingsId{Id: uint64(Id)})

	return err
}
