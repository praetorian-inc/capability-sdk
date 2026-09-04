package formatter_test

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
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

// aggregatorWaitTimeout bounds every wait in the cancellation test. The events
// waited on are microseconds apart in a healthy build, so a multi-second bound
// only fires on an aggregator regression, never because the machine is loaded.
const aggregatorWaitTimeout = 10 * time.Second

func TestAggregator_ContextCancellation(t *testing.T) {
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
	// the queue full and any further Submit unable to send.
	require.NoError(t, agg.Submit(context.Background(), formatter.Finding{ID: "queued"}))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.ErrorIs(t, agg.Submit(ctx, formatter.Finding{ID: "cancelled"}), context.Canceled)
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
	// full, and t.Fatal is illegal off the test goroutine. Cleanup always calls
	// releaseAll, so this receive cannot outlive the test.
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
