package cmd

import (
	"context"
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
		log.Info("Identity store cache is not ready yet")
		return []idpool.ID{}, nil
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

// difference returns the elements in `a` that aren't in `b`. The number of elements is capped by `maxElements`.
func difference(a, b []idpool.ID, maxElements int) []idpool.ID {
	mb := make(map[idpool.ID]struct{}, len(b))
	for _, x := range b {
		mb[x] = struct{}{}
	}
	var diff []idpool.ID
	for _, x := range a {
		if _, found := mb[x]; !found {
			diff = append(diff, x)
			if len(diff) == maxElements {
				return diff
			}
		}
	}
	return diff
}

func compareCRDAndKVStoreIdentities(ctx context.Context, kvstoreBackend kvstoreallocator.KVStoreBackend) {
	// Get CRD identities
	crdIdentityIds, err := getCRDIdentityIds()
	if err != nil {
		log.WithError(err).Error("Unable to get CRD identities")
		return
	}
	// Get KVStore identities
	kvstoreIdentityIds, err := kvstoreBackend.ListIDs(ctx)
	if err != nil {
		log.WithError(err).Error("Unable to get KVStore identities")
		return
	}
	// Compare CRD and KVStore identities
	maxDiffIDs := 5 // Cap the number of differing IDs so as not to log too many
	onlyInCrd := difference(crdIdentityIds, kvstoreIdentityIds, maxDiffIDs)
	onlyInKVStore := difference(kvstoreIdentityIds, crdIdentityIds, maxDiffIDs)
	log.Infof("CRD identities count: %d\n"+
		"KVStore identities: %d\n"+
		"Identities only in CRD count: %d. Example: %v\n"+
		"Identities only in KVStore count: %d. Example: %v\n",
		len(crdIdentityIds), len(kvstoreIdentityIds), len(onlyInCrd), onlyInCrd, len(onlyInKVStore), onlyInKVStore)
	// TODO report metrics as well
}

func startDoubleWriteMetricReporter(ctx context.Context, wg *sync.WaitGroup) {
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
