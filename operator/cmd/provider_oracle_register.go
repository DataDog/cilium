// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_oracle

package cmd

import (
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
)

func init() {
	allocatorProviders[ipamOption.IPAMOracle] = &allocatorOracle.AllocatorOracle{}
}
