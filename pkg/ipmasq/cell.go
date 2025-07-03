// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipmasq

import (
	"github.com/cilium/cilium/pkg/option"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/metrics"
)

// Cell provides the IPMasqAgent which manages the ip-masq-agent functionality.
// It watches configuration files and updates BPF maps accordingly.
var Cell = cell.Module(
	"ipmasq",
	"IP Masquerade Agent",

	cell.Provide(newIPMasqAgentCell),
	cell.Invoke(registerIPMasqAgentLifecycle),
	cell.Config(defaultConfig),
)

type ipMasqAgentParams struct {
	cell.In

	Logger          *slog.Logger
	Lifecycle       cell.Lifecycle
	JobGroup        job.Group
	MetricsRegistry *metrics.Registry
	Config          Config
}

type ipMasqAgentResult struct {
	cell.Out

	IPMasqAgent *IPMasqAgent
}

func newIPMasqAgentCell(params ipMasqAgentParams) (ipMasqAgentResult, error) {
	cfg := params.Config

	if !option.Config.EnableIPMasqAgent {
		return ipMasqAgentResult{}, nil
	}

	agent, err := NewIPMasqAgent(params.Logger, params.MetricsRegistry, cfg.IPMasqAgentConfigPath)
	if err != nil {
		return ipMasqAgentResult{}, err
	}

	return ipMasqAgentResult{
		IPMasqAgent: agent,
	}, nil
}

func registerIPMasqAgentLifecycle(
	params ipMasqAgentParams,
	agent *IPMasqAgent,
) {
	if agent == nil {
		return
	}

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			params.Logger.Info("Starting IP masquerade agent")
			agent.Start()
			return nil
		},
		OnStop: func(cell.HookContext) error {
			params.Logger.Info("Stopping IP masquerade agent")
			agent.Stop()
			return nil
		},
	})
}
