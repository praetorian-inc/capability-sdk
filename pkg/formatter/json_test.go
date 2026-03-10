package formatter_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/capability-sdk/pkg/formatter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJSONFormatter_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	f, err := formatter.New(formatter.Config{
		Format: formatter.FormatJSON,
		Writer: &buf,
	})
	require.NoError(t, err)

	err = f.Complete(context.Background(), formatter.Summary{})
	require.NoError(t, err)

	// Should be empty array
	var findings []formatter.Finding
	err = json.Unmarshal(buf.Bytes(), &findings)
	require.NoError(t, err)
	assert.Len(t, findings, 0)
}

func TestJSONFormatter_MultipleFindings(t *testing.T) {
	var buf bytes.Buffer
	f, err := formatter.New(formatter.Config{
		Format: formatter.FormatJSON,
		Writer: &buf,
	})
	require.NoError(t, err)

	testFindings := []formatter.Finding{
		{ID: "f1", Title: "Finding 1", Severity: formatter.SeverityHigh},
		{ID: "f2", Title: "Finding 2", Severity: formatter.SeverityMedium},
		{ID: "f3", Title: "Finding 3", Severity: formatter.SeverityLow},
	}

	for _, finding := range testFindings {
		err = f.Format(context.Background(), finding)
		require.NoError(t, err)
	}

	err = f.Complete(context.Background(), formatter.Summary{TotalFindings: 3})
	require.NoError(t, err)

	var decoded []formatter.Finding
	err = json.Unmarshal(buf.Bytes(), &decoded)
	require.NoError(t, err)
	assert.Len(t, decoded, 3)
	assert.Equal(t, "f1", decoded[0].ID)
	assert.Equal(t, "f2", decoded[1].ID)
	assert.Equal(t, "f3", decoded[2].ID)
}

func TestJSONFormatter_PrettyPrint(t *testing.T) {
	var buf bytes.Buffer
	f, err := formatter.New(formatter.Config{
		Format: formatter.FormatJSON,
		Writer: &buf,
		Pretty: true,
	})
	require.NoError(t, err)

	err = f.Format(context.Background(), formatter.Finding{ID: "test"})
	require.NoError(t, err)
	err = f.Complete(context.Background(), formatter.Summary{})
	require.NoError(t, err)

	// Pretty print should have indentation
	assert.Contains(t, buf.String(), "  ")
}

func TestJSONFormatter_BufferedInterface(t *testing.T) {
	var buf bytes.Buffer
	f, err := formatter.New(formatter.Config{
		Format: formatter.FormatJSON,
		Writer: &buf,
	})
	require.NoError(t, err)

	// Type assert to BufferedFormatter
	bf, ok := f.(formatter.BufferedFormatter)
	require.True(t, ok, "JSONFormatter should implement BufferedFormatter")

	assert.Equal(t, 0, bf.Len())

	f.Format(context.Background(), formatter.Finding{ID: "1"})
	f.Format(context.Background(), formatter.Finding{ID: "2"})
	assert.Equal(t, 2, bf.Len())

	bf.Reset()
	assert.Equal(t, 0, bf.Len())
}

func TestJSONFormatter_ContextCancellation(t *testing.T) {
	var buf bytes.Buffer
	f, err := formatter.New(formatter.Config{
		Format: formatter.FormatJSON,
		Writer: &buf,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = f.Format(ctx, formatter.Finding{ID: "test"})
	assert.ErrorIs(t, err, context.Canceled)
}
