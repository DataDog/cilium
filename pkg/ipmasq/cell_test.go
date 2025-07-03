// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipmasq

import (
	"context"
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
	)

	// Override configuration for the IPMasqAgent cell
	hive.AddConfigOverride(testHive, func(cfg *Config) {
		cfg.IPMasqAgentConfigPath = "/tmp/test-ipmasq-config"
	})

	// Start the hive
	ctx := context.Background()
	tlog := hivetest.Logger(t)
	err := testHive.Start(tlog, ctx)
	require.NoError(t, err)

	// Stop the hive
	err = testHive.Stop(tlog, ctx)
	require.NoError(t, err)
}

func TestIPMasqAgentCellDisabled(t *testing.T) {
	option.Config.EnableIPMasqAgent = false
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
	)

	// Start the hive
	ctx := context.Background()
	tlog := hivetest.Logger(t)
	err := testHive.Start(tlog, ctx)
	require.NoError(t, err)

	// Stop the hive
	err = testHive.Stop(tlog, ctx)
	require.NoError(t, err)
}

func TestIPMasqAgentCellDependencyInjection(t *testing.T) {
	option.Config.EnableIPMasqAgent = true
	var agent *IPMasqAgent

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
		cell.Invoke(func(a *IPMasqAgent) {
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

	// Stop the hive
	err = testHive.Stop(tlog, ctx)
	require.NoError(t, err)
}

// noOpShutdowner is a no-op implementation of hive.Shutdowner for testing
type noOpShutdowner struct{}

func (n *noOpShutdowner) Shutdown(opts ...upstreamHive.ShutdownOption) {}

// noOpLifecycle is a no-op implementation of cell.Lifecycle for testing
type noOpLifecycle struct{}

func (n *noOpLifecycle) Append(hook cell.HookInterface) {}

func (n *noOpLifecycle) Start(log *slog.Logger, ctx context.Context) error {
	return nil
}

func (n *noOpLifecycle) Stop(log *slog.Logger, ctx context.Context) error {
	return nil
}

func (n *noOpLifecycle) PrintHooks(w io.Writer) {}

// noOpJobGroup is a no-op implementation of job.Group for testing
type noOpJobGroup struct{}

func (n *noOpJobGroup) Add(jobs ...job.Job) {}

func (n *noOpJobGroup) Scoped(name string) job.ScopedGroup {
	return &noOpScopedGroup{}
}

// noOpScopedGroup is a no-op implementation of job.ScopedGroup for testing
type noOpScopedGroup struct{}

func (n *noOpScopedGroup) Add(jobs ...job.Job) {}
