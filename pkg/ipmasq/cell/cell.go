// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"fmt"
	"log/slog"

	"github.com/cilium/cilium/pkg/ipmasq"
	ipmasqmaps "github.com/cilium/cilium/pkg/maps/ipmasq"
	"github.com/cilium/cilium/pkg/option"

	"github.com/cilium/hive/cell"
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

	Logger    *slog.Logger
	Lifecycle cell.Lifecycle
	Config    Config
	IPMasqMap *ipmasqmaps.IPMasqBPFMap
}

type ipMasqAgentOut struct {
	cell.Out

	IPMasqAgent *ipmasq.IPMasqAgent
}

func newIPMasqAgentCell(params ipMasqAgentParams) (ipMasqAgentOut, error) {
	if !option.Config.EnableIPMasqAgent {
		return ipMasqAgentOut{}, nil
	}

	agent := ipmasq.NewIPMasqAgent(params.Config.IPMasqAgentConfigPath, params.IPMasqMap)

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
