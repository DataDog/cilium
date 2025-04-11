// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package list

import (
	"context"
	"fmt"
	"io"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/hubble/cmd/common/config"
	"github.com/cilium/cilium/hubble/cmd/common/conn"
	"github.com/cilium/cilium/hubble/cmd/common/template"
)

var endpointOpts struct {
	output string
}

// newEndpointCommand returns the endpoint command
func newEndpointCommand(vp *viper.Viper) *cobra.Command {
	endpointCmd := &cobra.Command{
		Use:     "endpoint [endpoint-id]",
		Aliases: []string{"endpoints"},
		Short:   "List policies attached to an endpoint",
		Long:    "List all policies that are attached to a specific endpoint",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("endpoint ID is required")
			}

			endpointID, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid endpoint ID: %s", args[0])
			}

			ctx := cmd.Context()
			hubbleConn, err := conn.New(ctx, vp.GetString(config.KeyServer), vp.GetDuration(config.KeyTimeout))
			if err != nil {
				return err
			}
			defer hubbleConn.Close()

			return runListEndpoint(ctx, cmd, hubbleConn, endpointID)
		},
	}

	flags := endpointCmd.Flags()
	flags.StringVarP(&endpointOpts.output, "output", "o", "table", "Output format: table, json")
	template.RegisterFlagSets(endpointCmd, config.ServerFlags)

	return endpointCmd
}

func runListEndpoint(ctx context.Context, cmd *cobra.Command, conn *grpc.ClientConn, endpointID int64) error {
	client := observerpb.NewObserverClient(conn)

	// Get endpoint policy status
	req := &observerpb.GetEndpointRequest{
		Number: endpointID,
	}

	resp, err := client.GetEndpoint(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to get endpoint policy: %w", err)
	}

	policy := resp.GetEndpoint().GetPolicy()
	if policy == nil {
		return fmt.Errorf("no policy found for endpoint %d", endpointID)
	}

	// Print policy information
	fmt.Fprintf(cmd.OutOrStdout(), "Endpoint %d Policy:\n", endpointID)
	fmt.Fprintf(cmd.OutOrStdout(), "  Policy Enabled: %s\n", policy.GetPolicyEnabled())
	fmt.Fprintf(cmd.OutOrStdout(), "  Policy Revision: %d\n", policy.GetPolicyRevision())

	// Print ingress policies
	fmt.Fprintf(cmd.OutOrStdout(), "\nIngress Policies:\n")
	for _, id := range policy.GetAllowedIngressIdentities() {
		fmt.Fprintf(cmd.OutOrStdout(), "  - Allowed Identity: %d\n", id)
	}
	for _, id := range policy.GetDeniedIngressIdentities() {
		fmt.Fprintf(cmd.OutOrStdout(), "  - Denied Identity: %d\n", id)
	}

	// Print egress policies
	fmt.Fprintf(cmd.OutOrStdout(), "\nEgress Policies:\n")
	for _, id := range policy.GetAllowedEgressIdentities() {
		fmt.Fprintf(cmd.OutOrStdout(), "  - Allowed Identity: %d\n", id)
	}
	for _, id := range policy.GetDeniedEgressIdentities() {
		fmt.Fprintf(cmd.OutOrStdout(), "  - Denied Identity: %d\n", id)
	}

	// Print L4 policies if available
	if l4 := policy.GetL4(); l4 != nil {
		fmt.Fprintf(cmd.OutOrStdout(), "\nL4 Policies:\n")
		if len(l4.GetIngress()) > 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "  Ingress Rules:\n")
			for _, rule := range l4.GetIngress() {
				fmt.Fprintf(cmd.OutOrStdout(), "  - %s\n", rule.GetRule())
			}
		}
		if len(l4.GetEgress()) > 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "  Egress Rules:\n")
			for _, rule := range l4.GetEgress() {
				fmt.Fprintf(cmd.OutOrStdout(), "  - %s\n", rule.GetRule())
			}
		}
	}

	return nil
}

func printPolicy(w io.Writer, policy *observerpb.EndpointPolicyStatus) error {
	if policy == nil {
		return nil
	}

	fmt.Fprintf(w, "Policy Revision: %d\n", policy.GetPolicyRevision())
	fmt.Fprintf(w, "Policy Enabled: %s\n", policy.GetPolicyEnabled())

	if policy.GetL4() != nil {
		fmt.Fprintln(w, "\nL4 Policy:")
		for _, ingress := range policy.GetL4().GetIngress() {
			fmt.Fprintf(w, "  Ingress: %s\n", ingress.GetRule())
		}
		for _, egress := range policy.GetL4().GetEgress() {
			fmt.Fprintf(w, "  Egress: %s\n", egress.GetRule())
		}
	}

	if len(policy.GetAllowedIngressIdentities()) > 0 {
		fmt.Fprintln(w, "\nAllowed Ingress Identities:")
		for _, id := range policy.GetAllowedIngressIdentities() {
			fmt.Fprintf(w, "  %d\n", id)
		}
	}

	if len(policy.GetAllowedEgressIdentities()) > 0 {
		fmt.Fprintln(w, "\nAllowed Egress Identities:")
		for _, id := range policy.GetAllowedEgressIdentities() {
			fmt.Fprintf(w, "  %d\n", id)
		}
	}

	if len(policy.GetDeniedIngressIdentities()) > 0 {
		fmt.Fprintln(w, "\nDenied Ingress Identities:")
		for _, id := range policy.GetDeniedIngressIdentities() {
			fmt.Fprintf(w, "  %d\n", id)
		}
	}

	if len(policy.GetDeniedEgressIdentities()) > 0 {
		fmt.Fprintln(w, "\nDenied Egress Identities:")
		for _, id := range policy.GetDeniedEgressIdentities() {
			fmt.Fprintf(w, "  %d\n", id)
		}
	}

	return nil
}
