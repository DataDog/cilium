// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipmasq

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides the IPMasqAgent which manages the ip-masq-agent functionality.
// It watches configuration files and updates BPF maps accordingly.
var Cell = cell.Module(
	"ipmasq",
	"IP Masquerade Agent",

	cell.Provide(newIPMasqAgentCell),
	cell.Invoke(registerIPMasqAgentLifecycle),
)

type ipMasqAgentParams struct {
	cell.In

	Logger          *slog.Logger
	Lifecycle       cell.Lifecycle
	JobGroup        job.Group
	MetricsRegistry *metrics.Registry
}

type ipMasqAgentResult struct {
	cell.Out

	IPMasqAgent *IPMasqAgent
}

func newIPMasqAgentCell(params ipMasqAgentParams) (ipMasqAgentResult, error) {
	if !option.Config.EnableIPMasqAgent {
		return ipMasqAgentResult{}, nil
	}

	agent, err := NewIPMasqAgent(params.Logger, params.MetricsRegistry, option.Config.IPMasqAgentConfigPath)
	if err != nil {
		return ipMasqAgentResult{}, err
	}

	return ipMasqAgentResult{
		IPMasqAgent: agent,
	}, nil
}

func registerIPMasqAgentLifecycle(
	lc cell.Lifecycle,
	params ipMasqAgentParams,
	result ipMasqAgentResult,
) {
	if result.IPMasqAgent == nil {
		return
	}

	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			params.Logger.Info("Starting IP masquerade agent")
			result.IPMasqAgent.Start()
			return nil
		},
		OnStop: func(cell.HookContext) error {
			params.Logger.Info("Stopping IP masquerade agent")
			result.IPMasqAgent.Stop()
			return nil
		},
	})
}
