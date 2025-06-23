// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipmasq

import (
	"context"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

func TestIPMasqAgentCell(t *testing.T) {
	// Create a test hive with the IPMasqAgent cell
	testHive := hive.New(
		Cell,
		cell.Provide(func() *metrics.Registry {
			return metrics.NewRegistry(metrics.RegistryParams{})
		}),
		cell.Provide(func() *option.DaemonConfig {
			// Create a minimal config for testing
			cfg := &option.DaemonConfig{}
			cfg.EnableIPMasqAgent = true
			cfg.IPMasqAgentConfigPath = "/tmp/test-ipmasq-config"
			return cfg
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

func TestIPMasqAgentCellDisabled(t *testing.T) {
	// Create a test hive with the IPMasqAgent cell but disabled
	testHive := hive.New(
		Cell,
		cell.Provide(func() *metrics.Registry {
			return metrics.NewRegistry(metrics.RegistryParams{})
		}),
		cell.Provide(func() *option.DaemonConfig {
			// Create a minimal config for testing with IPMasqAgent disabled
			cfg := &option.DaemonConfig{}
			cfg.EnableIPMasqAgent = false
			return cfg
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
	var agent *IPMasqAgent

	// Create a test hive that captures the IPMasqAgent
	testHive := hive.New(
		Cell,
		cell.Provide(func() *metrics.Registry {
			return metrics.NewRegistry(metrics.RegistryParams{})
		}),
		cell.Provide(func() *option.DaemonConfig {
			// Create a minimal config for testing
			cfg := &option.DaemonConfig{}
			cfg.EnableIPMasqAgent = true
			cfg.IPMasqAgentConfigPath = "/tmp/test-ipmasq-config"
			return cfg
		}),
		cell.Invoke(func(a *IPMasqAgent) {
			agent = a
		}),
	)

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
