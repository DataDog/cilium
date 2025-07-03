// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipmasq

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/option"
)

type Config struct {
	IPMasqAgentConfigPath string `mapstructure:"ip-masq-agent-config-path"`
}

var defaultConfig = Config{
	IPMasqAgentConfigPath: "/etc/config/ip-masq-agent",
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.String(option.IPMasqAgentConfigPath, c.IPMasqAgentConfigPath, "ip-masq-agent configuration file path")
}
