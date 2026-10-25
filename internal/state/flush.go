package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// CacheFlushWorker periodically flushes dirty sets to cache.db.
// It triggers a flush when:
//   - DirtyCount() >= threshold, OR
//   - time.Since(lastFlush) >= interval (and dirty count > 0)
//
// On Stop(), a final flush is performed before returning.
type CacheFlushWorker struct {
	engine      *StateEngine
	readers     CacheReaders
	thresholdFn func() int
	intervalFn  func() time.Duration
	checkTick   time.Duration // how often to check conditions

	stopCh            chan struct{}
	discardFinalFlush atomic.Bool
	wg                sync.WaitGroup
	stopOnce          sync.Once
	lifecycleMu       sync.Mutex
	flushMu           sync.Mutex
	started           bool
	stopped           bool
}

// ErrFlushDiscarded means this worker belongs to a retired slot. It must not
// write over the active slot's state, even when an authoritative flush is asked.
var ErrFlushDiscarded = errors.New("state: final flush was discarded")

// NewCacheFlushWorker creates a flush worker that pulls threshold/interval
// from callbacks on each check cycle.
// checkTick controls how often flush conditions are evaluated (e.g. 5s).
func NewCacheFlushWorker(
	engine *StateEngine,
	readers CacheReaders,
	thresholdFn func() int,
	intervalFn func() time.Duration,
	checkTick time.Duration,
) *CacheFlushWorker {
	if thresholdFn == nil {
		panic("state: NewCacheFlushWorker requires non-nil thresholdFn")
	}
	if intervalFn == nil {
		panic("state: NewCacheFlushWorker requires non-nil intervalFn")
	}
	if checkTick <= 0 {
		panic("state: NewCacheFlushWorker requires positive checkTick")
	}

	return &CacheFlushWorker{
		engine:      engine,
		readers:     readers,
		thresholdFn: thresholdFn,
		intervalFn:  intervalFn,
		checkTick:   checkTick,
		stopCh:      make(chan struct{}),
	}
}

// Start launches the background flush goroutine.
func (w *CacheFlushWorker) Start() {
	w.lifecycleMu.Lock()
	defer w.lifecycleMu.Unlock()
	if w.started || w.stopped {
		return
	}
	w.started = true
	w.wg.Add(1)
	go w.run()
}

// Stop signals the worker to stop and performs a final flush.
// Blocks until the goroutine exits.
func (w *CacheFlushWorker) Stop() {
	if err := w.StopAndFlush(); err != nil && !errors.Is(err, ErrFlushDiscarded) {
		log.Printf("[state] final flush error: %v", err)
	}
}

// StopAndFlush stops the periodic writer, then performs an error-returning
// final transaction. Callers MUST first stop and join all mutation sources;
// this is not a write barrier for the router, API or asynchronous callbacks.
// A successful retry supersedes an earlier periodic flush failure. Discard
// and this operation are serialized: a discarded slot can never be flushed.
func (w *CacheFlushWorker) StopAndFlush() error {
	w.lifecycleMu.Lock()
	defer w.lifecycleMu.Unlock()
	if w.discardFinalFlush.Load() {
		return ErrFlushDiscarded
	}
	w.stopped = true
	w.stopOnce.Do(func() { close(w.stopCh) })
	w.wg.Wait()
	if err := w.flush(); err != nil {
		return err
	}
	if pending := w.engine.DirtyCount(); pending != 0 {
		return fmt.Errorf("state: final flush left %d dirty entries; mutation sources are not quiescent", pending)
	}
	return nil
}

// Discard prevents the final flush performed by Stop. Use it only when the
// process is draining a blue/green slot that must not overwrite a newer
// state snapshot owned by the active slot.
func (w *CacheFlushWorker) Discard() {
	w.lifecycleMu.Lock()
	defer w.lifecycleMu.Unlock()
	// Finish any transaction already in progress before publishing Discard.
	// Once this point is reached no periodic or final writer can pass it.
	w.flushMu.Lock()
	w.discardFinalFlush.Store(true)
	w.flushMu.Unlock()
	w.stopped = true
	w.stopOnce.Do(func() { close(w.stopCh) })
	w.wg.Wait()
}

// DirtyCounts exposes the per-set pending work for the drain receipt.
func (w *CacheFlushWorker) DirtyCounts() map[string]int { return w.engine.DirtyCounts() }

// DrainReceipt is the hand-off record a drain-only slot writes before it
// suppresses its final flush. It proves which weak-persist sets were left to
// the active slot and how large they were; a reader can then insist that the
// active slot flushed them instead of assuming the retirement lost nothing.
type DrainReceipt struct {
	At          string         `json:"at"`
	Version     int            `json:"version"`
	Discard     bool           `json:"discardFinalFlush"`
	DirtyCounts map[string]int `json:"dirtyCounts"`
	DirtyTotal  int            `json:"dirtyTotal"`
}

// WriteDrainReceipt records the current dirty state next to the state store.
// It never flushes and never blocks shutdown: an unwritable receipt is logged
// and reported, because a missing receipt is safer than a stalled drain.
func (w *CacheFlushWorker) WriteDrainReceipt(stateDir string, discard bool, now time.Time) (string, error) {
	counts := w.engine.DirtyCounts()
	total := 0
	for _, value := range counts {
		total += value
	}
	receipt := DrainReceipt{At: now.UTC().Format(time.RFC3339Nano), Version: 1, Discard: discard,
		DirtyCounts: counts, DirtyTotal: total}
	data, err := json.Marshal(receipt)
	if err != nil {
		return "", err
	}
	path := filepath.Join(stateDir, "drain-receipt.json")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, append(data, '\n'), 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(temporary, path); err != nil {
		return "", fmt.Errorf("publish drain receipt: %w", err)
	}
	return path, nil
}

func (w *CacheFlushWorker) run() {
	defer w.wg.Done()

	ticker := time.NewTicker(w.checkTick)
	defer ticker.Stop()

	lastFlush := time.Now()

	for {
		select {
		case <-w.stopCh:
			// Only StopAndFlush owns the final transaction and its error.
			return
		case <-ticker.C:
			dirty := w.engine.DirtyCount()
			if dirty == 0 {
				continue // Skip empty flush.
			}

			threshold := w.thresholdFn()
			interval := w.intervalFn()
			if dirty >= threshold || time.Since(lastFlush) >= interval {
				w.doFlush()
				lastFlush = time.Now()
			}
		}
	}
}

func (w *CacheFlushWorker) doFlush() {
	if err := w.flush(); err != nil && !errors.Is(err, ErrFlushDiscarded) {
		log.Printf("[state] flush error (entries re-merged): %v", err)
	}
}

func (w *CacheFlushWorker) flush() error {
	w.flushMu.Lock()
	defer w.flushMu.Unlock()
	if w.discardFinalFlush.Load() {
		return ErrFlushDiscarded
	}
	return w.engine.FlushDirtySets(w.readers)
}
