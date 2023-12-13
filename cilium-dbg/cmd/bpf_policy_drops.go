// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/identity"
	identitymodel "github.com/cilium/cilium/pkg/identity/model"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
)

// bpfPolicyGetCmd represents the bpf_policy_get command
var bpfPolicyDropMetricsCmd = &cobra.Command{
	Use:   "drop_metrics",
	Short: "Get policy drop metrics",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf policy drop_metrics")
		if allList {
			listAllDropMaps()
			return
		}
		requireEndpointID(cmd, args)
		listDropMap(args)
	},
}

func init() {
	BPFPolicyCmd.AddCommand(bpfPolicyDropMetricsCmd)
	bpfPolicyDropMetricsCmd.Flags().BoolVarP(&printIDs, "numeric", "n", false, "Do not resolve IDs")
	bpfPolicyDropMetricsCmd.Flags().BoolVarP(&allList, "all", "", false, "Dump all policy maps")
	command.AddOutputOption(bpfPolicyDropMetricsCmd)
}

func listAllDropMaps() {
	mapRootPrefixPath := bpf.TCGlobalsPath()
	mapMatchExpr := filepath.Join(mapRootPrefixPath, "cilium_drop_*")

	matchFiles, err := filepath.Glob(mapMatchExpr)
	if err != nil {
		log.Fatal(err)
	}

	if len(matchFiles) == 0 {
		fmt.Println("no maps found")
		return
	}

	maps := []policyDropMap{}
	for _, file := range matchFiles {
		endpointSplit := strings.Split(file, "_")
		endpoint := strings.TrimLeft(endpointSplit[len(endpointSplit)-1], "0")
		maps = append(maps, policyDropMap{
			EndpointID: endpoint,
			Path:       file,
			Content:    dropMapContent(file),
		})
	}

	if command.OutputOption() {
		if err := command.PrintOutput(maps); err != nil {
			os.Exit(1)
		}
	} else {
		for _, m := range maps {
			fmt.Printf("Endpoint ID: %s\n", m.EndpointID)
			fmt.Printf("Path: %s\n", m.Path)
			fmt.Println()
			printDropTable(m.Content)
			fmt.Println()
			fmt.Println()
		}
	}
}

type policyDropMap struct {
	EndpointID string
	Path       string
	Content    policymap.PolicyDropEntriesDump
}

func listDropMap(args []string) {
	lbl := args[0]

	mapPath, err := endpointToPolicyMapPath(lbl)
	if err != nil {
		Fatalf("Failed to parse endpointID %q", lbl)
	}

	contentDump := dropMapContent(mapPath)
	if command.OutputOption() {
		if err := command.PrintOutput(contentDump); err != nil {
			os.Exit(1)
		}
	} else {
		printDropTable(contentDump)
	}
}

func dropMapContent(file string) policymap.PolicyDropEntriesDump {
	m, err := policymap.Open(file)
	if err != nil {
		Fatalf("Failed to open map: %s\n", err)
	}
	defer m.Close()

	statsMap, err := m.DumpToDropSlice()
	if err != nil {
		Fatalf("Error while opening bpf Map: %s\n", err)
	}
	//sort.Slice(statsMap, statsMap.Less)

	return statsMap
}

func printDropTable(contentDump policymap.PolicyDropEntriesDump) {
	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	formatDropMap(w, contentDump)
	w.Flush()
	if len(contentDump) == 0 {
		fmt.Printf("Policy stats empty. Perhaps the policy enforcement is disabled?\n")
	}
}

func formatDropMap(w io.Writer, statsMap []policymap.PolicyDropEntryDump) {
	const (
		trafficDirectionTitle = "DIRECTION"
		labelsIDTitle         = "IDENTITY"
		labelsDesTitle        = "LABELS (source:key[=value])"
		portTitle             = "PORT/PROTO"
		packetsTitle          = "DROP PACKETS"
	)

	labelsID := map[identity.NumericIdentity]*identity.Identity{}
	for _, stat := range statsMap {
		if !printIDs {
			id := identity.NumericIdentity(stat.Key.Identity)
			if lbls, err := client.IdentityGet(id.StringID()); err != nil {
				fmt.Fprintf(os.Stderr, "Was impossible to retrieve label ID %d: %s\n",
					id, err)
			} else {
				labelsID[id] = identitymodel.NewIdentityFromModel(lbls)
			}
		}

	}

	if printIDs {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t\n",
			trafficDirectionTitle, labelsIDTitle, portTitle, packetsTitle)
	} else {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t\n",
			trafficDirectionTitle, labelsDesTitle, portTitle, packetsTitle)
	}
	for _, stat := range statsMap {
		id := identity.NumericIdentity(stat.Key.Identity)
		trafficDirection := trafficdirection.TrafficDirection(stat.Key.TrafficDirection)
		trafficDirectionString := trafficDirection.String()
		port := stat.Key.PortProtoString()

		if printIDs {
			fmt.Fprintf(w, "%s\t%d\t%s\t%d\t\n",
				trafficDirectionString, id, port, stat.DropPackets)
		} else if lbls := labelsID[id]; lbls != nil && len(lbls.Labels) > 0 {
			first := true
			for _, lbl := range lbls.Labels.GetPrintableModel() {
				if first {
					fmt.Fprintf(w, "%s\t%s\t%s\t%d\t\n",
						trafficDirectionString, lbl, port, stat.DropPackets)
					first = false
				} else {
					fmt.Fprintf(w, "\t\t%s\t\t\t\t\t\t\t\n", lbl)
				}
			}
		} else {
			fmt.Fprintf(w, "%s\t%d\t%s\t%d\t\n",
				trafficDirectionString, id, port, stat.DropPackets)
		}
	}
}
