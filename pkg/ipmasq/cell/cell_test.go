// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"context"
	"net/netip"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/ipmasq"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

// dummyMap implements ipmasq.IPMasqMap with no-op behavior.
type dummyMap struct{}

func (d *dummyMap) Update(netip.Prefix) error     { return nil }
func (d *dummyMap) Delete(netip.Prefix) error     { return nil }
func (d *dummyMap) Dump() ([]netip.Prefix, error) { return nil, nil }

func TestIPMasqAgentCell(t *testing.T) {
	var agent *ipmasq.IPMasqAgent

	testHive := hive.New(
		// Needed for the metrics.Cell
		cell.Provide(func() *option.DaemonConfig { return &option.DaemonConfig{} }),
		// Needed for the IPMasqBPFMap
		metrics.Cell,
		// Provide a dummy IPMasq map to avoid touching real BPF maps.
		cell.Provide(func() ipmasq.IPMasqMap { return &dummyMap{} }),
		Cell,
		cell.Invoke(func(a *ipmasq.IPMasqAgent) {
			agent = a
		}),
	)

	configFile, err := os.CreateTemp("", "ipmasq-test")
	require.NoError(t, err)

	hive.AddConfigOverride(testHive, func(cfg *Config) {
		cfg.EnableIPMasqAgent = true
		cfg.IPMasqAgentConfigPath = configFile.Name()
	})

	// Start the hive
	ctx := context.Background()
	tlog := hivetest.Logger(t)
	err = testHive.Start(tlog, ctx)
	require.NoError(t, err)

	// Verify that the agent was successfully created
	assert.NotNil(t, agent)

	// Stop the hive
	err = testHive.Stop(tlog, ctx)
	require.NoError(t, err)
	os.Remove(configFile.Name())
}

func TestIPMasqAgentCellDisabled(t *testing.T) {
	var agent *ipmasq.IPMasqAgent

	testHive := hive.New(
		// Needed for the metrics.Cell
		cell.Provide(func() *option.DaemonConfig { return &option.DaemonConfig{} }),
		// Needed for the IPMasqBPFMap
		metrics.Cell,
		// Provide a dummy IPMasq map to avoid touching real BPF maps.
		cell.Provide(func() ipmasq.IPMasqMap { return &dummyMap{} }),
		Cell,
		cell.Invoke(func(a *ipmasq.IPMasqAgent) {
			agent = a
		}),
	)

	// Disable via config
	hive.AddConfigOverride(testHive, func(cfg *Config) {
		cfg.EnableIPMasqAgent = false
	})

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
