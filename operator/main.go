// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"github.com/cilium/cilium/operator/cmd"
	"github.com/cilium/cilium/pkg/hive"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

func main() {
	tracer.Start(
		tracer.WithEnv("experimental"),
		tracer.WithService("cilium-operator"),
	)
	defer tracer.Stop()

	operatorHive := hive.New(cmd.Operator)

	cmd.Execute(cmd.NewOperatorCmd(operatorHive))
}
