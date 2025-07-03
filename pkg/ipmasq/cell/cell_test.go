// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/cilium/cilium/pkg/ipmasq"

	upstreamHive "github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hive"
	ipmasqmaps "github.com/cilium/cilium/pkg/maps/ipmasq"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/option"
)

func TestIPMasqAgentCell(t *testing.T) {
	option.Config.EnableIPMasqAgent = true
	var agent *ipmasq.IPMasqAgent

	testHive := hive.New(
		ipmasqmaps.Cell,
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

	// Verify that the agent was successfully created
	assert.NotNil(t, agent)

	// Stop the hive
	err = testHive.Stop(tlog, ctx)
	require.NoError(t, err)
}

func TestIPMasqAgentCellDisabled(t *testing.T) {
	option.Config.EnableIPMasqAgent = false
	var agent *ipmasq.IPMasqAgent

	testHive := hive.New(
		ipmasqmaps.Cell,
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
