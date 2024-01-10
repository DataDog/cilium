package cmd

import (
	"context"
	"errors"
	"github.com/cilium/cilium/operator/metrics"
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/idpool"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/kvstore"
	kvstoreallocator "github.com/cilium/cilium/pkg/kvstore/allocator"
	"strconv"
	"sync"
)

func getCRDIdentityIds() ([]idpool.ID, error) {
	if identityStore == nil {
		return []idpool.ID{}, errors.New("identity store cache is not ready yet")
	}
	var identityIds []idpool.ID
	for _, identity := range identityStore.List() {
		idParsed, err := strconv.ParseUint(identity.(*v2.CiliumIdentity).Name, 10, 64)
		if err != nil {
			return []idpool.ID{}, err
		}
		identityIds = append(identityIds, idpool.ID(idParsed))
	}
	return identityIds, nil
}

// difference returns the elements in `a` that aren't in `b`
func difference(a, b []idpool.ID) []idpool.ID {
	mb := make(map[idpool.ID]struct{}, len(b))
	for _, x := range b {
		mb[x] = struct{}{}
	}
	var diff []idpool.ID
	for _, x := range a {
		if _, found := mb[x]; !found {
			diff = append(diff, x)
		}
	}
	return diff
}

func compareCRDAndKVStoreIdentities(ctx context.Context, kvstoreBackend kvstoreallocator.KVStoreBackend) {
	// Get CRD identities
	crdIdentityIds, err := getCRDIdentityIds()
	if err != nil {
		log.WithError(err).Warn("Unable to get CRD identities")
		return
	}

	// Get KVStore identities
	kvstoreIdentityIds, err := kvstoreBackend.ListIDs(ctx)
	if err != nil {
		log.WithError(err).Warn("Unable to get KVStore identities")
		return
	}

	// Compare CRD and KVStore identities
	onlyInCrd := difference(crdIdentityIds, kvstoreIdentityIds)
	onlyInKVStore := difference(kvstoreIdentityIds, crdIdentityIds)
	maxPrintedDiffIDs := 5 // Cap the number of differing IDs so as not to log too many
	log.Infof("CRD identities count: %d\n"+
		"KVStore identities: %d\n"+
		"Identities only in CRD: %d. Example IDs (capped at %d): %v\n"+
		"Identities only in KVStore: %d. Example IDs (capped at %d): %v\n",
		len(crdIdentityIds), len(kvstoreIdentityIds), len(onlyInCrd), maxPrintedDiffIDs, onlyInCrd[:maxPrintedDiffIDs], len(onlyInKVStore), maxPrintedDiffIDs, onlyInKVStore[:maxPrintedDiffIDs])

	metrics.IdentityCRDTotalCount.Set(float64(len(crdIdentityIds)))
	metrics.IdentityKVStoreTotalCount.Set(float64(len(kvstoreIdentityIds)))
	metrics.IdentityCRDOnlyCount.Set(float64(len(onlyInCrd)))
	metrics.IdentityKVStoreOnlyCount.Set(float64(len(onlyInKVStore)))
}

func startDoubleWriteMetricReporter(ctx context.Context, wg *sync.WaitGroup) {
	log.Info("Running the Double Write Metric Reporter")

	mgr := controller.NewManager()

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		mgr.RemoveAllAndWait()
	}()

	kvstoreBackend, err := kvstoreallocator.NewKVStoreBackend(kvstoreallocator.KVStoreBackendConfiguration{
		BasePath: cache.IdentitiesPath,
		Suffix:   "",
		Typ:      nil,
		Backend:  kvstore.Client(),
	})
	if err != nil {
		log.WithError(err).Fatal("Unable to initialize kvstore backend")
	}

	mgr.UpdateController("double-write-metric-reporter",
		controller.ControllerParams{
			RunInterval: operatorOption.Config.DoubleWriteMetricReporterInterval,
			DoFunc: func(ctx context.Context) error {
				compareCRDAndKVStoreIdentities(ctx, *kvstoreBackend)
				return ctx.Err()
			},
		})
}
