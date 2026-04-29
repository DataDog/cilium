// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_azure

package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/option"
)

func init() {
	FlagsHooks = append(FlagsHooks, &azureFlagsHooks{})
}

type azureFlagsHooks struct{}

func (hook *azureFlagsHooks) RegisterProviderFlag(cmd *cobra.Command, vp *viper.Viper) {
	flags := cmd.Flags()

	flags.String(operatorOption.AzureSubscriptionID, "", "Subscription ID to access Azure API")
	option.BindEnvWithLegacyEnvFallback(vp, operatorOption.AzureSubscriptionID, "AZURE_SUBSCRIPTION_ID")

	flags.String(operatorOption.AzureResourceGroup, "", "Resource group to use for Azure IPAM")
	option.BindEnvWithLegacyEnvFallback(vp, operatorOption.AzureResourceGroup, "AZURE_RESOURCE_GROUP")

	flags.String(operatorOption.AzureUserAssignedIdentityID, "", "ID of the user assigned identity used to auth with the Azure API")
	option.BindEnvWithLegacyEnvFallback(vp, operatorOption.AzureUserAssignedIdentityID, "AZURE_USER_ASSIGNED_IDENTITY_ID")

	flags.Bool(operatorOption.AzureUsePrimaryAddress, false, "Use Azure IP address from interface's primary IPConfigurations")
	option.BindEnvWithLegacyEnvFallback(vp, operatorOption.AzureUsePrimaryAddress, "AZURE_USE_PRIMARY_ADDRESS")

	flags.Bool(operatorOption.AzureReleaseExcessIPs, false, "Enable releasing excess free IP addresses from Azure NICs.")
	option.BindEnvWithLegacyEnvFallback(vp, operatorOption.AzureReleaseExcessIPs, "AZURE_RELEASE_EXCESS_IPS")

	// excess-ip-release-delay is shared with the AWS provider. Skip if AWS already registered it
	// (multi-provider cilium-operator binary).
	if flags.Lookup(operatorOption.ExcessIPReleaseDelay) == nil {
		flags.Int(operatorOption.ExcessIPReleaseDelay, 180, "Number of seconds operator would wait before it releases an IP previously marked as excess")
		option.BindEnv(vp, operatorOption.ExcessIPReleaseDelay)
	}

	vp.BindPFlags(flags)
}
