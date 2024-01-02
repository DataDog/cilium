package doublewrite

import (
	"context"
	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/k8s/identitybackend"
	"github.com/cilium/cilium/pkg/kvstore"
	kvstoreallocator "github.com/cilium/cilium/pkg/kvstore/allocator"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/rate"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "double-write-allocator")
)

func NewDoubleWriteBackend(c DoubleWriteBackendConfiguration) (allocator.Backend, error) {
	crdBackend, _ := identitybackend.NewCRDBackend(c.CRDBackendConfiguration)
	kvstoreBackend, _ := kvstoreallocator.NewKVStoreBackend(c.KVStoreBackendConfiguration)

	log.WithField("readFromKVStore", c.ReadFromKVStore).Info("Creating double-write backend with the following configuration: %+v", c)

	return &doubleWriteBackend{crdBackend: crdBackend.(*identitybackend.CRDBackend), kvstoreBackend: kvstoreBackend, readFromKVStore: c.ReadFromKVStore}, nil
}

type DoubleWriteBackendConfiguration struct {
	CRDBackendConfiguration     identitybackend.CRDBackendConfiguration
	KVStoreBackendConfiguration kvstoreallocator.KVStoreBackendConfiguration
	ReadFromKVStore             bool
}

type doubleWriteBackend struct {
	crdBackend      *identitybackend.CRDBackend
	kvstoreBackend  *kvstoreallocator.KVStoreBackend
	readFromKVStore bool
}

func (d *doubleWriteBackend) DeleteAllKeys(ctx context.Context) {
	d.crdBackend.DeleteAllKeys(ctx)
	d.kvstoreBackend.DeleteAllKeys(ctx)
}

func (d *doubleWriteBackend) AllocateID(ctx context.Context, id idpool.ID, key allocator.AllocatorKey) error {
	crdErr := d.crdBackend.AllocateID(ctx, id, key)
	kvStoreErr := d.kvstoreBackend.AllocateID(ctx, id, key)
	if d.readFromKVStore {
		return kvStoreErr
	}
	return crdErr
}

func (d *doubleWriteBackend) AllocateIDIfLocked(ctx context.Context, id idpool.ID, key allocator.AllocatorKey, lock kvstore.KVLocker) error {
	crdErr := d.crdBackend.AllocateIDIfLocked(ctx, id, key, lock)
	kvStoreErr := d.kvstoreBackend.AllocateIDIfLocked(ctx, id, key, lock)
	if d.readFromKVStore {
		return kvStoreErr
	}
	return crdErr
}

func (d *doubleWriteBackend) AcquireReference(ctx context.Context, id idpool.ID, key allocator.AllocatorKey, lock kvstore.KVLocker) error {
	crdErr := d.crdBackend.AcquireReference(ctx, id, key, lock)
	kvStoreErr := d.kvstoreBackend.AcquireReference(ctx, id, key, lock)
	if d.readFromKVStore {
		return kvStoreErr
	}
	return crdErr
}

func (d *doubleWriteBackend) RunLocksGC(ctx context.Context, staleKeysPrevRound map[string]kvstore.Value) (map[string]kvstore.Value, error) {
	// This is a no-op for the CRD backend
	return d.kvstoreBackend.RunLocksGC(ctx, staleKeysPrevRound)
}

func (d *doubleWriteBackend) RunGC(
	ctx context.Context,
	rateLimit *rate.Limiter,
	staleKeysPrevRound map[string]uint64,
	minID, maxID idpool.ID,
) (map[string]uint64, *allocator.GCStats, error) {
	// This is a no-op for the CRD backend
	return d.kvstoreBackend.RunGC(ctx, rateLimit, staleKeysPrevRound, minID, maxID)
}

func (d *doubleWriteBackend) UpdateKey(ctx context.Context, id idpool.ID, key allocator.AllocatorKey, reliablyMissing bool) error {
	crdErr := d.crdBackend.UpdateKey(ctx, id, key, reliablyMissing)
	kvStoreErr := d.kvstoreBackend.UpdateKey(ctx, id, key, reliablyMissing)
	if d.readFromKVStore {
		return kvStoreErr
	}
	return crdErr
}

func (d *doubleWriteBackend) UpdateKeyIfLocked(ctx context.Context, id idpool.ID, key allocator.AllocatorKey, reliablyMissing bool, lock kvstore.KVLocker) error {
	crdErr := d.crdBackend.UpdateKeyIfLocked(ctx, id, key, reliablyMissing, lock)
	kvStoreErr := d.kvstoreBackend.UpdateKeyIfLocked(ctx, id, key, reliablyMissing, lock)
	if d.readFromKVStore {
		return kvStoreErr
	}
	return crdErr
}

func (d *doubleWriteBackend) Lock(ctx context.Context, key allocator.AllocatorKey) (kvstore.KVLocker, error) {
	if d.readFromKVStore {
		return d.kvstoreBackend.Lock(ctx, key)
	}
	return &identitybackend.CRDLock{}, nil
}

func (d *doubleWriteBackend) Get(ctx context.Context, key allocator.AllocatorKey) (idpool.ID, error) {
	if d.readFromKVStore {
		return d.kvstoreBackend.Get(ctx, key)
	}
	return d.crdBackend.Get(ctx, key)
}

func (d *doubleWriteBackend) GetIfLocked(ctx context.Context, key allocator.AllocatorKey, lock kvstore.KVLocker) (idpool.ID, error) {
	if d.readFromKVStore {
		return d.kvstoreBackend.GetIfLocked(ctx, key, lock)
	}
	return d.crdBackend.GetIfLocked(ctx, key, lock)
}

func (d *doubleWriteBackend) GetByID(ctx context.Context, id idpool.ID) (allocator.AllocatorKey, error) {
	if d.readFromKVStore {
		return d.kvstoreBackend.GetByID(ctx, id)
	}
	return d.crdBackend.GetByID(ctx, id)
}

func (d *doubleWriteBackend) Release(ctx context.Context, id idpool.ID, key allocator.AllocatorKey) (err error) {
	if d.readFromKVStore {
		return d.kvstoreBackend.Release(ctx, id, key)
	}
	// Release does nothing in the CRD backend
	return nil
}

func (d *doubleWriteBackend) ListAndWatch(ctx context.Context, handler allocator.CacheMutations, stopChan chan struct{}) {
	d.crdBackend.ListAndWatch(ctx, handler, stopChan)
	d.kvstoreBackend.ListAndWatch(ctx, handler, stopChan)
}

func (d *doubleWriteBackend) Status() (string, error) {
	if d.readFromKVStore {
		return d.kvstoreBackend.Status()
	}
	return d.crdBackend.Status()
}

func (d *doubleWriteBackend) Encode(v string) string {
	// Works for both CRD and etcd KVStore
	return v
}
