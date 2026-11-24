package state

import (
	"fmt"
	"log"
	"sync"
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

	stopCh      chan struct{}
	wg          sync.WaitGroup
	stopOnce    sync.Once
	lifecycleMu sync.Mutex
	flushMu     sync.Mutex
	started     bool
	stopped     bool
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
	if err := w.StopAndFlush(); err != nil {
		log.Printf("[state] final flush error: %v", err)
	}
}

// StopAndFlush stops the periodic writer, then performs an error-returning
// final transaction. Callers MUST first stop and join all mutation sources;
// this is not a write barrier for the router, API or asynchronous callbacks.
// A successful retry supersedes an earlier periodic flush failure.
func (w *CacheFlushWorker) StopAndFlush() error {
	w.lifecycleMu.Lock()
	defer w.lifecycleMu.Unlock()
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
	if err := w.flush(); err != nil {
		log.Printf("[state] flush error (entries re-merged): %v", err)
	}
}

func (w *CacheFlushWorker) flush() error {
	w.flushMu.Lock()
	defer w.flushMu.Unlock()
	return w.engine.FlushDirtySets(w.readers)
}
