// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"context"
	"github.com/cilium/cilium/pkg/ipmasq"
	"io"
	"log/slog"
	"testing"

	upstreamHive "github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/option"
)

func TestIPMasqAgentCell(t *testing.T) {
	option.Config.EnableIPMasqAgent = true
	var agent *ipmasq.IPMasqAgent

	testHive := hive.New(
		Cell,
		cell.Provide(func() *metrics.Registry {
			return metrics.NewRegistry(metrics.RegistryParams{
				Logger:       slog.Default(),
				Shutdowner:   &noOpShutdowner{},
				Lifecycle:    &noOpLifecycle{},
				AutoMetrics:  []metric.WithMetadata{},
				Config:       metrics.RegistryConfig{},
				DaemonConfig: &option.DaemonConfig{},
			})
		}),
		cell.Invoke(func(a *ipmasq.IPMasqAgent) {
			agent = a
		}),
	)

	hive.AddConfigOverride(testHive, func(cfg *Config) {
		cfg.IPMasqAgentConfigPath = "/tmp/test-ipmasq-config"
	})

	// Start the hive
	ctx := context.Background()
	tlog := hivetest.Logger(t)
	err := testHive.Start(tlog, ctx)
	require.NoError(t, err)

	// Verify that the agent was created
	assert.NotNil(t, agent)
	assert.Equal(t, "/tmp/test-ipmasq-config", agent.configPath)

	// Stop the hive
	err = testHive.Stop(tlog, ctx)
	require.NoError(t, err)
}

func TestIPMasqAgentCellDisabled(t *testing.T) {
	option.Config.EnableIPMasqAgent = false
	var agent *ipmasq.IPMasqAgent

	testHive := hive.New(
		Cell,
		cell.Provide(func() *metrics.Registry {
			return metrics.NewRegistry(metrics.RegistryParams{
				Logger:       slog.Default(),
				Shutdowner:   &noOpShutdowner{},
				Lifecycle:    &noOpLifecycle{},
				AutoMetrics:  []metric.WithMetadata{},
				Config:       metrics.RegistryConfig{},
				DaemonConfig: &option.DaemonConfig{},
			})
		}),
		cell.Invoke(func(a *ipmasq.IPMasqAgent) {
			agent = a
		}),
	)

	// Start the hive
	ctx := context.Background()
	tlog := hivetest.Logger(t)
	err := testHive.Start(tlog, ctx)
	require.NoError(t, err)

	// Verify that the agent was not created
	assert.Nil(t, agent)

	// Stop the hive
	err = testHive.Stop(tlog, ctx)
	require.NoError(t, err)
}

type noOpShutdowner struct{}

func (n *noOpShutdowner) Shutdown(...upstreamHive.ShutdownOption) {}

type noOpLifecycle struct{}

func (n *noOpLifecycle) Append(cell.HookInterface) {}
func (n *noOpLifecycle) Start(*slog.Logger, context.Context) error {
	return nil
}
func (n *noOpLifecycle) Stop(*slog.Logger, context.Context) error {
	return nil
}
func (n *noOpLifecycle) PrintHooks(io.Writer) {}

type noOpJobGroup struct{}

func (n *noOpJobGroup) Add(...job.Job) {}
func (n *noOpJobGroup) Scoped(string) job.ScopedGroup {
	return &noOpScopedGroup{}
}

type noOpScopedGroup struct{}

func (n *noOpScopedGroup) Add(...job.Job) {}
