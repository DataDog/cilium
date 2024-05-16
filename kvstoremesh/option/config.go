// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/option"
)

const (
	// PprofAddress is the default value for pprof in kvstoremesh
	PprofAddress = "localhost"

	// PprofPort is the default value for pprof in kvstoremesh
	PprofPort = 6064
)

// Config is the KVStoreMeshConfig configuration.
type KVStoreMeshConfig struct {
	Debug bool

	ClusterName string
	ClusterID   uint32

	LogDriver []string
	LogOpt    map[string]string
}

func (def KVStoreMeshConfig) Flags(flags *pflag.FlagSet) {
	flags.BoolP(option.DebugArg, "D", def.Debug, "Enable debugging mode")
	flags.String(option.ClusterName, def.ClusterName, "Name of the cluster")
	flags.Uint32(option.ClusterIDName, def.ClusterID, "Unique identifier of the cluster")
	flags.StringSlice(option.LogDriver, def.LogDriver, "Logging driver to use")
	flags.Var(option.NewNamedMapOptions(option.LogOpt, &option.Config.LogOpt, nil), option.LogOpt, "Logger options")
}
