// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package compute

import (
	"context"
	"runtime"
	"sync"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/policy"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/time"
)

type PolicyRecomputer interface {
	RecomputeIdentityPolicy(identity *identity.Identity, toRev uint64) (<-chan struct{}, error)
	RecomputeIdentityPolicyForAllIdentities(toRev uint64) (*statedb.WatchSet, error)
	UpdatePolicy(idsToRegen set.Set[identity.NumericIdentity], fromRev, toRev uint64)
	GetIdentityPolicyByNumericIdentity(identity identity.NumericIdentity) (Result, statedb.Revision, <-chan struct{}, bool)
	GetIdentityPolicyByIdentity(identity *identity.Identity) (Result, statedb.Revision, <-chan struct{}, bool)
	GetAuthTypes(localID, remoteID identity.NumericIdentity) policyTypes.AuthTypes
	GetPolicySnapshot() map[identity.NumericIdentity]policy.SelectorPolicy
}

type Result struct {
	Identity             identity.NumericIdentity
	NewPolicy, OldPolicy policy.SelectorPolicy
	Revision             uint64
	Err                  error
}

type computeRequest struct {
	identity *identity.Identity
	toRev    uint64
	done     chan struct{}
	// attempt counts how many times computing this identity's policy has
	// already failed. It drives the retry backoff in processRequests.
	attempt int
}

const (
	// retryBackoffBase is the delay before the first recomputation retry after
	// a failure. It doubles per attempt up to retryBackoffMax.
	retryBackoffBase = 100 * time.Millisecond
	// retryBackoffMax caps the retry delay. Failures here are usually
	// transient (e.g. a cert fetch), so the cap stays well inside the window
	// an endpoint regeneration is willing to wait.
	retryBackoffMax = 5 * time.Second
)

// retryBackoff returns the delay before retrying a computation that has already
// failed attempt times.
func retryBackoff(attempt int) time.Duration {
	d := retryBackoffBase << min(attempt, 16)
	return min(d, retryBackoffMax)
}

func (r *IdentityPolicyComputer) UpdatePolicy(idsToRegen set.Set[identity.NumericIdentity], _, toRev uint64) {
	// The lock order is IdentityManager.mutex before reqsMu, since the
	// IdentityManager observer takes reqsMu. Resolve identities, which takes
	// IdentityManager.mutex, before locking reqsMu.
	ids := make([]*identity.Identity, 0, idsToRegen.Len())
	for id := range idsToRegen.Members() {
		if idd := r.idmanager.Get(&id); idd != nil {
			ids = append(ids, idd)
		} else {
			r.logger.Debug("Policy recomputation skipped due to non-local identity", logfields.Identity, id)
		}
	}

	r.reqsMu.Lock()
	for _, idd := range ids {
		r.enqueueLocked(idd, toRev)
	}
	r.reqsMu.Unlock()
	r.notifyTrigger()
}

// enqueueLocked appends or coalesces a request and returns the done channel.
// Must be called with r.reqsMu held. The caller must notifyTrigger after
// unlocking.
func (r *IdentityPolicyComputer) enqueueLocked(identity *identity.Identity, toRev uint64) <-chan struct{} {
	return r.appendLocked(computeRequest{
		identity: identity,
		toRev:    toRev,
		done:     make(chan struct{}),
	})
}

// appendLocked appends req, preserving its attempt count if an entry for the
// same identity is already queued. Must be called with r.reqsMu held.
func (r *IdentityPolicyComputer) appendLocked(req computeRequest) <-chan struct{} {
	for i, existing := range r.reqs {
		if existing.identity.ID != req.identity.ID {
			continue
		}
		if req.toRev > existing.toRev {
			r.reqs[i].toRev = req.toRev
		}
		// Keep the higher attempt count so a coalescing fresh request cannot
		// reset the backoff of an identity that keeps failing.
		r.reqs[i].attempt = max(r.reqs[i].attempt, req.attempt)
		return r.reqs[i].done
	}
	r.reqs = append(r.reqs, req)
	return req.done
}

func (r *IdentityPolicyComputer) notifyTrigger() {
	select {
	case r.trigger <- struct{}{}:
	default:
	}
}

// scheduleRetries re-enqueues failed computations after a per-identity backoff.
//
// Requeueing immediately turns a persistently failing identity into a busy loop
// that starves every other computation of the CPU it needs, which is precisely
// when endpoints are most likely to time out waiting. Retries are grouped by
// delay so a batch of failures costs one timer per distinct delay, not one per
// identity.
func (r *IdentityPolicyComputer) scheduleRetries(ctx context.Context, retry []computeRequest) {
	if len(retry) == 0 {
		return
	}
	byDelay := make(map[time.Duration][]computeRequest, 4)
	for _, req := range retry {
		d := retryBackoff(req.attempt)
		byDelay[d] = append(byDelay[d], req)
	}
	for delay, reqs := range byDelay {
		r.logger.Debug("Scheduling policy computation retry",
			logfields.Count, len(reqs),
			logfields.Duration, delay)
		time.AfterFunc(delay, func() {
			if ctx.Err() != nil {
				// processRequests has already drained and closed the queue on
				// shutdown; close these too so nothing is left waiting.
				for _, req := range reqs {
					close(req.done)
				}
				return
			}
			r.reqsMu.Lock()
			for _, req := range reqs {
				r.appendLocked(req)
			}
			r.reqsMu.Unlock()
			r.notifyTrigger()
		})
	}
}

// RecomputeIdentityPolicy schedules a policy recomputation for identity at
// toRev. The returned channel closes once the result is committed to the
// table. A pending request for the same identity is reused, bumping its toRev
// to max(existing, toRev), so there is at most one in-flight request per
// identity.
func (r *IdentityPolicyComputer) RecomputeIdentityPolicy(identity *identity.Identity, toRev uint64) (<-chan struct{}, error) {
	r.reqsMu.Lock()
	done := r.enqueueLocked(identity, toRev)
	r.reqsMu.Unlock()
	r.notifyTrigger()
	return done, nil
}

// RecomputeIdentityPolicyForAllIdentities recomputes policy for all local identities.
func (r *IdentityPolicyComputer) RecomputeIdentityPolicyForAllIdentities(toRev uint64) (*statedb.WatchSet, error) {
	ws := statedb.NewWatchSet()

	r.logger.Info("Recomputing policy for all identities")
	// GetAll takes IdentityManager.mutex. Call it before locking reqsMu (see
	// UpdatePolicy).
	ids := r.idmanager.GetAll()

	r.reqsMu.Lock()
	for _, id := range ids {
		ws.Add(r.enqueueLocked(id, toRev))
	}
	r.reqsMu.Unlock()
	r.notifyTrigger()
	return ws, nil
}

func (r *IdentityPolicyComputer) GetIdentityPolicyByNumericIdentity(identity identity.NumericIdentity) (Result, statedb.Revision, <-chan struct{}, bool) {
	return r.tbl.GetWatch(r.db.ReadTxn(), PolicyComputationByIdentity(identity))
}

func (r *IdentityPolicyComputer) GetIdentityPolicyByIdentity(identity *identity.Identity) (Result, statedb.Revision, <-chan struct{}, bool) {
	if identity == nil {
		return Result{}, 0, nil, false
	}
	return r.GetIdentityPolicyByNumericIdentity(identity.ID)
}

// processRequests drains computation requests and processes them in batches.
// Single requests are processed immediately. Bursts are naturally batched.
func (r *IdentityPolicyComputer) processRequests(ctx context.Context) error {
	type pending struct {
		computeRequest
		rev       statedb.Revision      // statedb revision for CompareAndSwap
		found     bool                  // whether a row for this identity is already committed
		oldPolicy policy.SelectorPolicy // the committed policy, superseded after the new one commits
	}

	for {
		select {
		case <-ctx.Done():
			// Close any queued requests so waiters don't hang.
			r.reqsMu.Lock()
			abandoned := r.reqs
			r.reqs = nil
			r.reqsMu.Unlock()
			r.logger.Debug("Draining pending policy computation requests on shutdown", logfields.Count, len(abandoned))
			for _, req := range abandoned {
				close(req.done)
			}
			return nil
		case <-r.trigger:
		}

		r.reqsMu.Lock()
		batch := r.reqs
		r.reqs = nil
		r.reqsMu.Unlock()
		if len(batch) == 0 {
			continue
		}

		r.logger.Debug("Processing policy computation batch", logfields.Count, len(batch))

		// Check which requests actually need computation.
		rtxn := r.db.ReadTxn()
		var work []pending
		for _, req := range batch {
			obj, rev, found := r.tbl.Get(rtxn, PolicyComputationByIdentity(req.identity.ID))
			// An error row carries no policy and has Revision 0, so it must
			// never satisfy a request -- otherwise a toRev of 0 (what
			// LocalEndpointIdentityAdded and the retries themselves use) would
			// match it and the identity would stay failed forever.
			if found && obj.Err == nil && obj.Revision >= req.toRev {
				close(req.done)
				continue
			}
			// The currently committed policy becomes the old one once this
			// recomputation commits its replacement.
			work = append(work, pending{computeRequest: req, rev: rev, found: found, oldPolicy: obj.NewPolicy})
		}
		if len(work) == 0 {
			continue
		}

		type result struct {
			pending
			res Result
		}
		results := make([]result, len(work))
		// Bound the fan-out. Each ComputeSelectorPolicy is CPU-bound and holds
		// repo.mutex for reading, so spawning one goroutine per identity does
		// not increase throughput once every core is busy: it just multiplies
		// scheduler pressure and read-lock holders competing with the policy
		// importer's writer. Under a CPU quota (the agent normally runs with
		// one) an unbounded batch is markedly slower in wall-clock than a
		// bounded one, which is what pushes endpoint waiters over their
		// deadline during a restart.
		sem := make(chan struct{}, max(1, runtime.GOMAXPROCS(0)))
		var wg sync.WaitGroup
		for i, w := range work {
			wg.Go(func() {
				sem <- struct{}{}
				defer func() { <-sem }()

				start := time.Now()
				results[i].pending = w
				results[i].res.Identity = w.identity.ID
				results[i].res.OldPolicy = w.oldPolicy
				results[i].res.NewPolicy, results[i].res.Revision, results[i].res.Err = r.repo.ComputeSelectorPolicy(w.identity)
				outcome := metrics.LabelValueOutcomeSuccess
				if results[i].res.Err != nil {
					outcome = metrics.LabelValueOutcomeFailure
				}
				metrics.EndpointRegenerationTimeStats.
					WithLabelValues("selectorPolicyCalculation", outcome).
					Observe(time.Since(start).Seconds())
			})
		}
		wg.Wait()

		// Commit in a single WriteTxn.
		wtxn := r.db.WriteTxn(r.tbl)
		var retry []computeRequest
		for i := range results {
			if err := results[i].res.Err; err != nil {
				// This error will result in the relevant endpoints failing
				// to regenerate.
				r.logger.Error("Policy computation failed for identity",
					logfields.Identity, results[i].res.Identity,
					logfields.Attempt, results[i].attempt+1,
					logfields.Error, err,
				)
				// Re-enqueue so a transient failure (e.g. cert fetch)
				// doesn't leave statedb without an entry forever. Dropping a
				// computation would leave endpoints on a stale policy, so we
				// always retry, but with a backoff: a permanently failing
				// identity used to spin here, burning the CPU that every
				// other identity's computation is waiting on.
				retry = append(retry, computeRequest{
					identity: results[i].identity,
					toRev:    results[i].toRev,
					done:     make(chan struct{}),
					attempt:  results[i].attempt + 1,
				})
				// With no committed policy for this identity there is nothing
				// for a waiting endpoint to fall back on, and an absent row is
				// indistinguishable from "not computed yet" -- so the endpoint
				// would block until its own deadline and then report a
				// misleading "not found in statedb". Record the failure so it
				// surfaces the actual cause instead. Where a policy is already
				// committed we leave it alone: the last good policy is a better
				// answer than an error, and the retry will replace it.
				if !results[i].found {
					errRes := Result{Identity: results[i].identity.ID, Err: err}
					if _, _, cerr := r.tbl.CompareAndSwap(wtxn, results[i].rev, errRes); cerr != nil {
						r.logger.Debug("Failed to record policy computation error",
							logfields.Identity, results[i].identity.ID,
							logfields.Error, cerr)
					}
				}
				results[i].res = Result{}
				continue
			}
			// CAS failure means a delete for this identity raced us. The
			// new policy was Attach()ed by resolvePolicyLocked, so supersede
			// it here to release its SelectorCache references. The old policy
			// is released by the delete path in LocalEndpointIdentityRemoved.
			if _, _, err := r.tbl.CompareAndSwap(wtxn, results[i].rev, results[i].res); err != nil {
				if results[i].res.NewPolicy != nil {
					results[i].res.NewPolicy.Supersede()
				}
				results[i].res = Result{}
			}
		}
		wtxn.Commit()

		r.scheduleRetries(ctx, retry)

		for _, cr := range results {
			close(cr.done)
			if cr.res.Identity == 0 {
				continue // CAS failed
			}
			r.logger.Debug("Policy recomputation completed",
				logfields.Identity, cr.res.Identity,
				logfields.PolicyRevision, cr.toRev,
			)
			if cr.res.OldPolicy != nil {
				cr.res.OldPolicy.Supersede()
			}
		}
	}
}

// LocalEndpointIdentityAdded is part of the identitymanager.Observer
// interface.
//
// The subject selectorcache must be updated with the identity before
// recomputation, otherwise policy will not be computed properly.
func (r *IdentityPolicyComputer) LocalEndpointIdentityAdded(id *identity.Identity) {
	r.repo.UpdateIdentities(identity.IdentityMap{id.ID: id.LabelArray}, nil)
	_, _ = r.RecomputeIdentityPolicy(id, 0)
}

// LocalEndpointIdentityRemoved is part of the identitymanager.Observer interface.
func (r *IdentityPolicyComputer) LocalEndpointIdentityRemoved(id *identity.Identity) {
	r.logger.Debug("Identity removed", logfields.Identity, id.ID)

	// See comment on LocalEndpointIdentityAdded.
	r.repo.UpdateIdentities(nil, identity.IdentityMap{id.ID: id.LabelArray})

	// Drop any pending compute requests for this identity so we don't keep
	// re-running a stale computation.
	r.reqsMu.Lock()
	kept := r.reqs[:0]
	for _, req := range r.reqs {
		if req.identity.ID == id.ID {
			close(req.done)
			continue
		}
		kept = append(kept, req)
	}
	r.reqs = kept
	r.reqsMu.Unlock()

	wtxn := r.db.WriteTxn(r.tbl)
	obj, _, found := r.tbl.Get(wtxn, PolicyComputationByIdentity(id.ID))
	if !found {
		wtxn.Abort()
		return
	}
	if _, _, err := r.tbl.Delete(wtxn, obj); err != nil {
		wtxn.Abort()
		r.logger.Error("Failed to delete from policy computation table",
			logfields.Identity, id.ID,
			logfields.Error, err)
		return
	}
	wtxn.Commit()

	// Release the policy's selectors. Supersede after Commit so the detach
	// runs outside the write txn, matching processRequests.
	if obj.NewPolicy != nil {
		obj.NewPolicy.Supersede()
	}
}
