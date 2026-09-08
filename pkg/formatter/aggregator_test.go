package formatter_test

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/praetorian-inc/capability-sdk/pkg/formatter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAggregator_SingleSubmit(t *testing.T) {
	var buf bytes.Buffer
	f, err := formatter.New(formatter.Config{
		Format: formatter.FormatNDJSON,
		Writer: &buf,
	})
	require.NoError(t, err)

	agg := formatter.NewAggregator(f, 10)

	err = agg.Submit(context.Background(), formatter.Finding{
		ID:    "test-1",
		Title: "Test Finding",
	})
	require.NoError(t, err)

	err = agg.Close()
	require.NoError(t, err)

	assert.Contains(t, buf.String(), "test-1")
}

func TestAggregator_ConcurrentSubmits(t *testing.T) {
	var buf bytes.Buffer
	f, err := formatter.New(formatter.Config{
		Format: formatter.FormatNDJSON,
		Writer: &buf,
	})
	require.NoError(t, err)

	agg := formatter.NewAggregator(f, 100)

	var wg sync.WaitGroup
	numGoroutines := 10
	findingsPerGoroutine := 10

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < findingsPerGoroutine; j++ {
				assert.NoError(t, agg.Submit(context.Background(), formatter.Finding{
					ID:    fmt.Sprintf("g%d-f%d", goroutineID, j),
					Title: "Concurrent Finding",
				}))
			}
		}(i)
	}

	wg.Wait()
	err = agg.Close()
	require.NoError(t, err)

	// Count lines in output
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	assert.Len(t, lines, numGoroutines*findingsPerGoroutine)
}

// aggregatorWaitTimeout bounds every wait in the cancellation tests. The events
// waited on are microseconds apart in a healthy build, so a multi-second bound
// only fires on an aggregator regression, never because the machine is loaded.
const aggregatorWaitTimeout = 10 * time.Second

// TestAggregator_ContextCancellation pins both of Submit's cancellation exits.
// Submit (aggregator.go:57-81) checks ctx.Done() twice: once in the
// non-blocking select at :63-68, and again in the blocking select at :74-79
// that its default case falls through to. Both return ctx.Err(), so the return
// value alone cannot tell them apart - each subtest below reaches exactly one.
func TestAggregator_ContextCancellation(t *testing.T) {
	t.Run("cancelled before submit returns from the non-blocking select", func(t *testing.T) {
		agg, _ := newSaturatedAggregator(t)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		// The queue is full, so the send case cannot proceed, and ctx.Done() is
		// already closed. The first select therefore has exactly one ready
		// case and returns at aggregator.go:67 without reaching its default.
		assert.ErrorIs(t, agg.Submit(ctx, formatter.Finding{ID: "cancelled"}), context.Canceled)
	})

	t.Run("cancelled while blocked returns from the blocking select", func(t *testing.T) {
		agg, f := newSaturatedAggregator(t)

		// The cleanup registered below owns cancellation, so the context is
		// released even if an assertion between here and there fails.
		ctx, cancel := context.WithCancel(context.Background())
		obs := &doneObserver{Context: ctx, entered: make(chan struct{})}

		// Buffered, so the sender never blocks handing back its result, and a
		// separate close signals return without competing for that value.
		submitted := make(chan error, 1)
		returned := make(chan struct{})
		go func() {
			defer close(returned)
			submitted <- agg.Submit(obs, formatter.Finding{ID: "cancelled"})
		}()

		// Cleanups run LIFO, so this one runs before the release-and-close that
		// newSaturatedAggregator registered, and it must leave no goroutine
		// parked on the aggregator's channel for Close to close underneath.
		t.Cleanup(func() {
			cancel()
			select {
			case <-returned:
				return
			case <-time.After(aggregatorWaitTimeout):
			}
			t.Errorf("Submit did not return %s after its context was cancelled", aggregatorWaitTimeout)

			// Only reachable if Submit ignored cancellation. Draining the queue
			// lets that send complete, so the failure above is what gets
			// reported rather than a "send on closed channel" panic in Close
			// that would abort the binary and discard it.
			f.releaseAll()
			select {
			case <-returned:
			case <-time.After(aggregatorWaitTimeout):
				t.Errorf("Submit still parked on the queue %s after it drained", aggregatorWaitTimeout)
			}
		})

		obs.waitEntered(t)
		cancel()

		// The worker stays parked inside Format until cleanup releases it, so
		// the queue stays full and the blocking select's send case can never
		// become ready. Its only reachable exit is ctx.Done() at :78.
		assert.ErrorIs(t, waitForErr(t, submitted, "Submit to return"), context.Canceled)
	})
}

// newSaturatedAggregator returns an aggregator whose only worker is parked
// inside Format and whose one-slot buffer is full, so any further Submit must
// fall through to the blocking select at aggregator.go:74. The formatter is
// returned so a caller can drain the queue early; cleanup drains it regardless.
func newSaturatedAggregator(t *testing.T) (*formatter.FormatterAggregator, *blockingFormatter) {
	t.Helper()

	f := newBlockingFormatter()
	agg := formatter.NewAggregator(f, 1)

	// Registered as soon as agg exists so that a failing require below cannot
	// skip it and leave the worker blocked on a channel nobody closes.
	// Releasing before closing lets the worker drain and exit, where closing
	// first would deadlock Close's wg.Wait against the parked Format.
	t.Cleanup(func() {
		f.releaseAll()
		_ = agg.Close()
	})

	// The worker dequeues this finding and parks inside Format...
	require.NoError(t, agg.Submit(context.Background(), formatter.Finding{ID: "processing"}))
	waitFor(t, f.started, "the formatter to enter Format")

	// ...so this one fills the buffer the worker has stopped draining, leaving
	// the queue full for the rest of the subtest.
	require.NoError(t, agg.Submit(context.Background(), formatter.Finding{ID: "queued"}))

	return agg, f
}

// doneObserver reports when Submit enters its blocking select. A select
// evaluates each of its channel operands exactly once on entry (Go spec,
// "Select statements"), and Submit reads ctx.Done() in exactly two selects, so
// the second evaluation proves the non-blocking select chose its default and
// that Submit is committed to the blocking select at aggregator.go:74.
type doneObserver struct {
	context.Context

	calls   atomic.Int64
	entered chan struct{}
}

func (c *doneObserver) Done() <-chan struct{} {
	// Add returns a distinct value per call, so exactly one caller closes.
	if c.calls.Add(1) == 2 {
		close(c.entered)
	}
	return c.Context.Done()
}

func (c *doneObserver) waitEntered(t *testing.T) {
	t.Helper()

	select {
	case <-c.entered:
	case <-time.After(aggregatorWaitTimeout):
		t.Fatalf("Submit did not enter its blocking select within %s: saw %d ctx.Done() evaluations, want 2",
			aggregatorWaitTimeout, c.calls.Load())
	}
}

// waitFor bounds a receive that should already be imminent, so an aggregator
// that never gets there fails with a diagnostic instead of hanging until the
// package test timeout.
func waitFor(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()

	select {
	case <-ch:
	case <-time.After(aggregatorWaitTimeout):
		t.Fatalf("timed out after %s waiting for %s", aggregatorWaitTimeout, what)
	}
}

func waitForErr(t *testing.T, ch <-chan error, what string) error {
	t.Helper()

	select {
	case err := <-ch:
		return err
	case <-time.After(aggregatorWaitTimeout):
		t.Fatalf("timed out after %s waiting for %s", aggregatorWaitTimeout, what)
		return nil
	}
}

type blockingFormatter struct {
	started chan struct{}
	release chan struct{}

	startedOnce sync.Once
	releaseOnce sync.Once
}

func newBlockingFormatter() *blockingFormatter {
	return &blockingFormatter{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (f *blockingFormatter) Initialize(context.Context, formatter.ToolInfo) error { return nil }
func (f *blockingFormatter) Complete(context.Context, formatter.Summary) error    { return nil }
func (f *blockingFormatter) Close() error                                         { return nil }

func (f *blockingFormatter) Format(context.Context, formatter.Finding) error {
	f.startedOnce.Do(func() { close(f.started) })
	// Deliberately unbounded: parking here is what keeps the aggregator's queue
	// full, and t.Fatal is illegal off the test goroutine. Every subtest's
	// cleanup calls releaseAll, so this receive cannot outlive the test.
	<-f.release
	return nil
}

// releaseAll unblocks every Format call. Safe to call more than once.
func (f *blockingFormatter) releaseAll() {
	f.releaseOnce.Do(func() { close(f.release) })
}

func TestAggregator_SubmitAfterClose(t *testing.T) {
	var buf bytes.Buffer
	f, _ := formatter.New(formatter.Config{
		Format: formatter.FormatNDJSON,
		Writer: &buf,
	})

	agg := formatter.NewAggregator(f, 10)
	require.NoError(t, agg.Close())

	err := agg.Submit(context.Background(), formatter.Finding{ID: "test"})
	assert.ErrorIs(t, err, formatter.ErrAggregatorClosed)
}
