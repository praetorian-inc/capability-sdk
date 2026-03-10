package formatter_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/praetorian-inc/capability-sdk/pkg/formatter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNDJSONFormatter_SingleFinding(t *testing.T) {
	var buf bytes.Buffer
	f, err := formatter.New(formatter.Config{
		Format: formatter.FormatNDJSON,
		Writer: &buf,
	})
	require.NoError(t, err)

	err = f.Format(context.Background(), formatter.Finding{
		ID:       "test-1",
		Title:    "Test Finding",
		Severity: formatter.SeverityHigh,
	})
	require.NoError(t, err)

	// Should be valid JSON
	var decoded formatter.Finding
	err = json.Unmarshal(buf.Bytes(), &decoded)
	require.NoError(t, err)
	assert.Equal(t, "test-1", decoded.ID)
}

func TestNDJSONFormatter_MultipleFindings(t *testing.T) {
	var buf bytes.Buffer
	f, err := formatter.New(formatter.Config{
		Format: formatter.FormatNDJSON,
		Writer: &buf,
	})
	require.NoError(t, err)

	findings := []formatter.Finding{
		{ID: "f1", Title: "Finding 1", Severity: formatter.SeverityHigh},
		{ID: "f2", Title: "Finding 2", Severity: formatter.SeverityMedium},
		{ID: "f3", Title: "Finding 3", Severity: formatter.SeverityLow},
	}

	for _, finding := range findings {
		err = f.Format(context.Background(), finding)
		require.NoError(t, err)
	}

	// Each line should be valid JSON
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	assert.Len(t, lines, 3)

	for i, line := range lines {
		var decoded formatter.Finding
		err = json.Unmarshal([]byte(line), &decoded)
		require.NoError(t, err, "line %d should be valid JSON", i)
	}
}

func TestNDJSONFormatter_ContextCancellation(t *testing.T) {
	var buf bytes.Buffer
	f, err := formatter.New(formatter.Config{
		Format: formatter.FormatNDJSON,
		Writer: &buf,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err = f.Format(ctx, formatter.Finding{ID: "test"})
	assert.ErrorIs(t, err, context.Canceled)
}
