// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"github.com/cilium/cilium/operator/cmd"
	"github.com/cilium/cilium/pkg/hive"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
	"gopkg.in/DataDog/dd-trace-go.v1/profiler"
)

func main() {
	tracer.Start(
		tracer.WithEnv("staging"),
		tracer.WithService("cilium-operator"),
	)
	defer tracer.Stop()

	profiler.Start(
		profiler.WithService("cilium-operator"),
		profiler.WithEnv("staging"),
		profiler.WithProfileTypes(
			profiler.CPUProfile,
			profiler.HeapProfile,
			profiler.BlockProfile,
			profiler.MutexProfile,
			profiler.GoroutineProfile,
		),
	)
	defer profiler.Stop()

	operatorHive := hive.New(cmd.Operator)

	cmd.Execute(cmd.NewOperatorCmd(operatorHive))
}
