// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package azure

import (
	"context"
	"fmt"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/allocator"
	ipamMetrics "github.com/cilium/cilium/pkg/ipam/metrics"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/oracle/api"
	oracleIPAM "github.com/cilium/cilium/pkg/oracle/ipam"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ipam-allocator-oci")

type AllocatorOracle struct{}

func (*AllocatorOracle) Init(ctx context.Context) error { return nil }

// Start kicks of the OCI IP allocation
func (*AllocatorOracle) Start(ctx context.Context, getterUpdater ipam.CiliumNodeGetterUpdater) (allocator.NodeEventHandler, error) {

	log.Info("Starting OCI IP allocator...")

	oracleClient, err := api.NewClient("ocid1.compartment.oc1..aaaaaaaaitgyzv36mdj2n5txiiugwpvrlienkvztyzn27xxduwlcemtmbawa")
	if err != nil {
		return nil, fmt.Errorf("unable to create OCI client: %w", err)
	}
	instances := oracleIPAM.NewInstancesManager(*oracleClient, "ocid1.vcn.oc1.iad.amaaaaaapvn52dyahvu33tvs5jejngcr4mda76l3suebupnqkjs5w3osqehq")

	// TODO config option to release IPs
	nodeManager, err := ipam.NewNodeManager(instances, getterUpdater, &ipamMetrics.NoOpMetrics{}, operatorOption.Config.ParallelAllocWorkers, true, false)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize OCI node manager: %w", err)
	}

	if err := nodeManager.Start(ctx); err != nil {
		return nil, err
	}

	return nodeManager, nil
}
