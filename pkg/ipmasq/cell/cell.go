// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"fmt"
	"github.com/cilium/cilium/pkg/ipmasq"
	"github.com/cilium/cilium/pkg/option"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/metrics"
)

var Cell = cell.Module(
	"ip-masq-agent",
	"BPF ip-masq-agent implementation",

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

type ipMasqAgentOut struct {
	cell.Out

	IPMasqAgent *ipmasq.IPMasqAgent
}

func newIPMasqAgentCell(params ipMasqAgentParams) (ipMasqAgentOut, error) {
	cfg := params.Config

	if !option.Config.EnableIPMasqAgent {
		return ipMasqAgentOut{}, nil
	}

	agent := ipmasq.NewIPMasqAgent(params.Logger, params.MetricsRegistry, cfg.IPMasqAgentConfigPath)

	return ipMasqAgentOut{
		IPMasqAgent: agent,
	}, nil
}

func registerIPMasqAgentLifecycle(
	params ipMasqAgentParams,
	agent *ipmasq.IPMasqAgent,
) {
	if agent == nil {
		return
	}

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			params.Logger.Info("Starting ip-masq-agent")
			err := agent.Start()
			if err != nil {
				return fmt.Errorf("failed to start ip-masq-agent: %w", err)
			}
			return nil
		},
		OnStop: func(cell.HookContext) error {
			params.Logger.Info("Stopping ip-masq-agent")
			agent.Stop()
			return nil
		},
	})
}
