package state

import (
	"encoding/json"
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
}

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
	w.wg.Add(1)
	go w.run()
}

// Stop signals the worker to stop and performs a final flush.
// Blocks until the goroutine exits.
func (w *CacheFlushWorker) Stop() {
	w.stopOnce.Do(func() { close(w.stopCh) })
	w.wg.Wait()
}

// Discard prevents the final flush performed by Stop. Use it only when the
// process is draining a blue/green slot that must not overwrite a newer
// state snapshot owned by the active slot.
func (w *CacheFlushWorker) Discard() {
	w.discardFinalFlush.Store(true)
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
			// Final flush before exit.
			if !w.discardFinalFlush.Load() {
				w.doFlush()
			}
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
	if err := w.engine.FlushDirtySets(w.readers); err != nil {
		log.Printf("[state] flush error (entries re-merged): %v", err)
	}
}
