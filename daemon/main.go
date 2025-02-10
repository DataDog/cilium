// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"github.com/cilium/cilium/daemon/cmd"
	"github.com/cilium/cilium/pkg/hive"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

func main() {
	tracer.Start(
		tracer.WithService("cilium-agent"),
		tracer.WithAnalyticsRate(1),
	)
	defer tracer.Stop()
	agentHive := hive.New(cmd.Agent)

	cmd.Execute(cmd.NewAgentCmd(agentHive))
}
