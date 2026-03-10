package formatter

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
)

// FormatterAggregator serializes concurrent finding submissions to a single formatter.
// Safe for concurrent use from multiple goroutines.
type FormatterAggregator struct {
	formatter Formatter
	findings  chan Finding
	wg        sync.WaitGroup

	closed atomic.Bool
	mu     sync.Mutex
	err    error
}

// NewAggregator creates an aggregator wrapping the given formatter.
// bufferSize controls how many findings can be queued before Submit blocks.
func NewAggregator(f Formatter, bufferSize int) *FormatterAggregator {
	if bufferSize <= 0 {
		bufferSize = 100
	}

	a := &FormatterAggregator{
		formatter: f,
		findings:  make(chan Finding, bufferSize),
	}

	a.wg.Add(1)
	go a.worker()

	return a
}

// worker processes findings from the channel
func (a *FormatterAggregator) worker() {
	defer a.wg.Done()

	for finding := range a.findings {
		if err := a.formatter.Format(context.Background(), finding); err != nil {
			a.mu.Lock()
			if a.err == nil {
				a.err = err
			}
			a.mu.Unlock()
		}
	}
}

// Submit queues a finding for formatting. Safe for concurrent use.
// Returns error if context is cancelled or aggregator is closed.
func (a *FormatterAggregator) Submit(ctx context.Context, f Finding) error {
	// Check closed first to avoid send on closed channel
	if a.closed.Load() {
		return ErrAggregatorClosed
	}

	select {
	case a.findings <- f:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		// Channel full, check if closed again before blocking
		if a.closed.Load() {
			return ErrAggregatorClosed
		}
		// Block on send
		select {
		case a.findings <- f:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Close stops accepting findings and waits for pending writes to complete.
// Returns any error encountered during formatting.
func (a *FormatterAggregator) Close() error {
	a.closed.Store(true)
	close(a.findings)
	a.wg.Wait()

	a.mu.Lock()
	defer a.mu.Unlock()
	return a.err
}

// Err returns any error encountered during formatting.
func (a *FormatterAggregator) Err() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.err
}

// ErrAggregatorClosed is returned when Submit is called after Close.
var ErrAggregatorClosed = fmt.Errorf("aggregator is closed")
