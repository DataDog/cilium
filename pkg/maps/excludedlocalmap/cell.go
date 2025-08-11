// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package excludedlocalmap

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
)

var Cell = cell.Module(
	"excluded-local-addresses-map",
	"eBPF map which stores excluded local addresses",

	cell.Provide(newExcludedLocalMap),
)

func newExcludedLocalMap(lifecycle cell.Lifecycle) bpf.MapOut[*ExcludedLocalMap] {
	excludedLocalMap := &ExcludedLocalMap{}

	lifecycle.Append(cell.Hook{
		OnStart: func(context cell.HookContext) error {
			return excludedLocalMap.init()
		},
		OnStop: func(context cell.HookContext) error {
			return excludedLocalMap.close()
		},
	})

	return bpf.NewMapOut(excludedLocalMap)
}
