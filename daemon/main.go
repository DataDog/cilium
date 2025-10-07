// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"github.com/cilium/cilium/daemon/cmd"
	"github.com/cilium/cilium/pkg/hive"
	"gopkg.in/DataDog/dd-trace-go.v1/profiler"
)

func main() {

	profiler.Start(
		profiler.WithService("cilium"),
		profiler.WithProfileTypes(
			profiler.CPUProfile,
			profiler.HeapProfile,
			profiler.BlockProfile,
		),
	)
	defer profiler.Stop()
	hiveFn := func() *hive.Hive {
		return hive.New(cmd.Agent)
	}
	cmd.Execute(cmd.NewAgentCmd(hiveFn))
}
