package formatter_test

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

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
				agg.Submit(context.Background(), formatter.Finding{
					ID:    fmt.Sprintf("g%d-f%d", goroutineID, j),
					Title: "Concurrent Finding",
				})
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

func TestAggregator_ContextCancellation(t *testing.T) {
	var buf bytes.Buffer
	f, _ := formatter.New(formatter.Config{
		Format: formatter.FormatNDJSON,
		Writer: &buf,
	})

	// Buffer size 1, fill it first
	agg := formatter.NewAggregator(f, 1)

	// Fill the buffer so next submit blocks
	err := agg.Submit(context.Background(), formatter.Finding{ID: "fill"})
	require.NoError(t, err)

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// This should return context.Canceled because buffer is full and context is cancelled
	err = agg.Submit(ctx, formatter.Finding{ID: "test"})
	assert.ErrorIs(t, err, context.Canceled)

	agg.Close()
}

func TestAggregator_SubmitAfterClose(t *testing.T) {
	var buf bytes.Buffer
	f, _ := formatter.New(formatter.Config{
		Format: formatter.FormatNDJSON,
		Writer: &buf,
	})

	agg := formatter.NewAggregator(f, 10)
	agg.Close()

	err := agg.Submit(context.Background(), formatter.Finding{ID: "test"})
	assert.ErrorIs(t, err, formatter.ErrAggregatorClosed)
}
