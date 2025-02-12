// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_oracle

package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/option"
)

func init() {
	FlagsHooks = append(FlagsHooks, &ociFlagsHooks{})
}

type ociFlagsHooks struct{}

func (hook *ociFlagsHooks) RegisterProviderFlag(cmd *cobra.Command, vp *viper.Viper) {
	flags := cmd.Flags()

	flags.String(operatorOption.OracleCompartmentID, "", "Compartment ID")
	option.BindEnv(vp, operatorOption.OracleCompartmentID)

	vp.BindPFlags(flags)
}
