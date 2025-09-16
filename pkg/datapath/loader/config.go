// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"log/slog"

	"github.com/cilium/cilium/pkg/datapath/config"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/option"
)

func nodeConfig(lnc *datapath.LocalNodeConfiguration) config.Node {
	node := *config.NewNode()

	if lnc.ServiceLoopbackIPv4 != nil {
		node.ServiceLoopbackIPv4 = [4]byte(lnc.ServiceLoopbackIPv4.To4())
	}

	if lnc.CiliumInternalIPv6 != nil {
		node.RouterIPv6 = ([16]byte)(lnc.CiliumInternalIPv6.To16())
	}

	node.TracePayloadLen = uint32(option.Config.TracePayloadlen)
	node.TracePayloadLenOverlay = uint32(option.Config.TracePayloadlenOverlay)

	if option.Config.PolicyDenyResponse == option.PolicyDenyResponseIcmp {
		node.PolicyDenyResponseEnabled = 1
		slog.Info("New config system: Enabling policy deny response ICMP",
			"policy-deny-response", option.Config.PolicyDenyResponse,
			"PolicyDenyResponseEnabled", node.PolicyDenyResponseEnabled)
	} else {
		node.PolicyDenyResponseEnabled = 0
		slog.Info("New config system: Disabling policy deny response ICMP",
			"policy-deny-response", option.Config.PolicyDenyResponse,
			"PolicyDenyResponseEnabled", node.PolicyDenyResponseEnabled)
	}

	return node
}
